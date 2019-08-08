from time import sleep
import threading
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os
from time import sleep
import codecs
import time
import socket
import sys
import spidev
import RPi.GPIO as GPIO

#communicate with lnd rpc server
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
cert = open(os.path.expanduser('/home/bitcoin/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10001', creds)
stub = lnrpc.LightningStub(channel)

#Listen on socket for incomming connections (from a client)
HOST = '192.168.10.10'  # Standard loopback interface address (localhost)
PORT = 2000        # Port to listen on (non-privileged ports are > 1023)

# set up channel for spidev
channel = 0

# set GPIO pin for LED
go_led = 15
stop_led = 14
led_state = True

global conn
global flow_level
global in_use
global spi
global tap_open


def stop_go_led(go):
    global go_led
    global stop_led

    if(go==True):
        GPIO.output(go_led, GPIO.HIGH)
        GPIO.output(stop_led, GPIO.LOW)
    else:
        GPIO.output(go_led, GPIO.LOW)
        GPIO.output(stop_led, GPIO.HIGH)



def setup():
    global spi
    global go_led
    global stop_led

    #spidev 
    spi = spidev.SpiDev()
    spi.open(0,0)
    spi.max_speed_hz=999999

    #GPIO pins
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(go_led, GPIO.OUT)
    GPIO.setup(stop_led, GPIO.OUT)


def GetData(channel): # channel must be an integer 0-7
    global spi

    adc = spi.xfer2([1,(8+channel)<<4,0]) # sending 3 bytes
    data = ((adc[1]&3) << 8) + adc[2]
    return data

def ConvertVolts(data,places):
    volts = (data * 3.3) / float(1023)
    volts = round(volts,places)
    return volts

def pole_the_pot():
    global flow_level
    global spi
    global tap_open

    while in_use:
        sensor_data = GetData(channel)
        sensor_volt = ConvertVolts(sensor_data, 2)
        flow_level =int(round((10/3.3)*sensor_volt)) 
        if(flow_level==0):
            tap_open = False
        time.sleep(0.5)

def start_socket_connection():
    global conn

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print("Socket Error : %s" % msg)
        sys.exit()

    try:
        s.listen()
    except KeyboardInterrupt:
        s.close()
        sys.exit()

    conn, addr = s.accept()
    print('Got connection from '+str(addr))


def get_settings():
    global max_level
    global intervals

    print("----------------Welcome-----------------------")
    max_level = int(input("Enter max level: "))
    intervals = float(input("Enter charging intervals: "))
    print("Once you start, use 'u' and 'd' to increase and decrease the flow and 'q' to stop the session")
    print("----------------------------------------------")
    input("Press Enter to start using the resource")

def generate_invoice():
    global flow_level
    global conn

    amount = flow_level
    memo = "Bob's resource. Flow level: "+str(flow_level)+"/10"
    response = stub.AddInvoice(ln.Invoice(value=amount, memo=memo))
    pay_req = response.payment_request

    conn.send(pay_req.encode())

    return pay_req

def check_for_payment(pay_req):
    response = stub.DecodePayReq(ln.PayReqString(pay_req=pay_req))
    payment_hash = codecs.decode(response.payment_hash, 'hex')
    invoice = stub.LookupInvoice(ln.PaymentHash(r_hash = payment_hash))
    status = invoice.settled
    return status

def wait_for_payment(pay_req):
    response = stub.DecodePayReq(ln.PayReqString(pay_req=pay_req))
    payment_hash = codecs.decode(response.payment_hash, 'hex')

    status = False
    start_time = time.time()
    duration = time.time()-start_time
    
    while status == False and duration < 2:
        invoice = stub.LookupInvoice(ln.PaymentHash(r_hash = payment_hash))
        status = invoice.settled
        duration = time.time()-start_time

    if(status==True):
        stop_go_led(True)
        return True
    else:
        stop_go_led(False)
        return False

    

def resource_in_use():
    global in_use
    global flow_level
    global conn
    global tap_open

    flow_level = 0
    amount_received = 0
    num_payments = 0

    while in_use:

        os.system('clear')
        print("----------------------------------------------------")
        print("Total Satoshi's Received: "+str(amount_received))
        print("----------------------------------------------------")
        print("Num payments received: "+str(num_payments))
        print("Tap status: "+str(flow_level)+"/"+str(10))
        print("----------------------------------------------------")

        if(flow_level==0):
            print("Tap is closed. No charge")
        else:

            print("generating invoice for flow level of: "+str(round(flow_level, 3)))

            pay_req = generate_invoice()
            print(pay_req)

            rec_pay = wait_for_payment(pay_req)
            
            if(rec_pay):
                num_payments += 1
                amount_received += flow_level
                print("Got Payment!")
            else:
                in_use = False
                print("Did not receive payment in time. Supply is being cut")

def welcome():

    os.system('clear')
    print("---------------------------------------------------------------")
    print("                  WELCOME TO BOB'S TAP                         ")
    print("---------------------------------------------------------------")
    print("To start using this tap you must connect your lightning device ")
    print("to the following address: ")
    print("                    "+HOST+":"+str(PORT))
    print("---------------------------------------------------------------")
    print("Waiting for connection.....")


def main():
    global conn
    global in_use
    global tap_open
    
    #setup spidev and gpio pins etc 
    setup()

    #stop light
    stop_go_led(False)

    #welcome message
    welcome()

    #listen for client (user wallet)
    start_socket_connection()

    #go light
    stop_go_led(True)
    
    tap_open = True
    in_use = True
    
    #get settings from user
    #get_settings()

    #start key poller on separate thread
    poller = threading.Thread(target=pole_the_pot)
    poller.start()

    #start main resource functionality on the main thread
    resource_in_use()

    #Stop the keypoller thread
    poller.join()

    #close the socket connection to clint 
    conn.send(b"end")
    conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        spi.close()
        conn.close()
        GPIO.cleanup()
    
    exit()
    GPIO.cleanup()

