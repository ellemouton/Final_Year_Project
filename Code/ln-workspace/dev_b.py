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

#communicate with lnd rpc server
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10002', creds)
stub = lnrpc.LightningStub(channel)

#Listen on socket for incomming connections (from a client)
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

global conn
global flow_level
global max_level
global intervals
global in_use


def keyboard_poller():
    global flow_level
    global max_level
    global in_use

    while in_use:
        ch = input(">")
        if ch=="u":
            if(flow_level >= max_level):
                print("Maximum Resource Flow")
            else:
                flow_level += 1

        elif ch=="d":
            if(flow_level <= 0):
                print("Tap is closed")
            else:
                flow_level -= 1

        else:
            in_use = False


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
    global max_level
    global conn

    amount = flow_level
    memo = "Bob's resource. Flow level: "+str(flow_level)+"/"+str(max_level)
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

def resource_in_use():
    global in_use
    global flow_level
    global max_level
    global conn

    flow_level = 0
    amount_received = 0
    num_payments = 0
    wait_times  = []

    while in_use:
        os.system('clear')
        print("----------------------------------------------------")
        print("Total Satoshi's Received: "+str(amount_received))
        print("----------------------------------------------------")
        print("Num payments received: "+str(num_payments))
        print("Tap status: "+str(flow_level)+"/"+str(max_level))
        print("Payments generated every: "+str(intervals)+"s")
        print("'u' to increase flow")
        print("'d' to decrease flow")
        print("----------------------------------------------------")

        if(flow_level==0):
            print("Tap is closed. No charge")
        else:

            print("generating invoice for flow level of: "+str(flow_level))
            start = time.time()
            pay_req = generate_invoice()

            count = 0
            while (check_for_payment(pay_req)==False):
                count += 1

            elapsed_time = time.time()-start

            num_payments += 1
            amount_received += flow_level
            wait_times.append(elapsed_time)
            print("Got Payment!")

        sleep(intervals)

    conn.send(b"end")
    print(wait_times)


def main():
    global conn
    global in_use

    #listen for client (user wallet)
    start_socket_connection()

    #get settings from user
    get_settings()

    #start key poller on separate thread
    in_use = True
    poller = threading.Thread(target=keyboard_poller)
    poller.start()

    #start main resource functionality on the main thread
    resource_in_use()

    #Stop the keypoller thread
    poller.join()

    #close the socket connection to clint
    conn.close()


if __name__ == "__main__":
    print("Started...")

    main()

    exit()
