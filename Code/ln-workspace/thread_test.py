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

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10002', creds)
stub = lnrpc.LightningStub(channel)

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()
print("socket is listening")


global flow_level
global max_level
global loop

def keyboard_poller():
    global flow_level
    global loop

    while loop:
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
            loop = False

def generate_invoice():
    global flow_level
    global max_level

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

def main():
    global max_level
    global flow_level
    global loop

    print("----------------Welcome-----------------------")
    max_level = int(input("Enter max level: "))
    intervals = float(input("Enter charging intervals: "))
    print("Once you start, use 'u' and 'd' to increase and decrease the flow and 'q' to stop the session")
    input("Press Enter to start using the resource")
    amount_received = 0
    num_payments = 0

    flow_level = 0
    loop = True

    poller = threading.Thread(target=keyboard_poller)
    poller.start()

    wait_times = []

    while loop:
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
           # print("...Waiting for payment...")

            count = 0
            while (check_for_payment(pay_req)==False):
                count += 1

            elapsed_time = time.time()-start

            num_payments += 1
            amount_received += flow_level
            wait_times.append(elapsed_time)
            print("Got Payment!")

        sleep(intervals)

    poller.join()
    print(wait_times)
    conn.close()

if __name__ == "__main__":
    print("Started..")

    while True:
        main()

    input("Press any key to exit...")
    exit()
