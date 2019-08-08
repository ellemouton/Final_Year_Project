import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os
from time import sleep
import codecs
import socket
import sys
import time

#connection to lnd rpc server
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10001', creds)
stub = lnrpc.LightningStub(channel)

#socket details of Device B
#HOST = '192.168.10.10'  # The server's hostname or IP address
#PORT = 2000        # The port used by the server

global sock
global content

def connect_to_resource_socket(host, port):
    global sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except socket.error as msg:
        print("Socket Error : %s" % msg)
        sys.exit()

def listen_for_invoice():
    global content

    content = sock.recv(1024)
    print(content)
    if len(content)>0 and  not (content == b'end'):
        return True
    elif content==b'end':
        print("\n------------Session closed---------------")
    return False

def request_generator():
    global content

    total_sent = 0

    print("Starting up")

    while True:

        if listen_for_invoice():
            os.system('clear')
            print("--------------------------------------")
            print("Total Satoshi's Sent: "+str(total_sent))
            print("--------------------------------------")

            request = ln.SendRequest(payment_request=content)

            print("--------New Payment Details---------")
            pay_req = stub.DecodePayReq(ln.PayReqString(pay_req = content))
            print("Memo: "+str(pay_req.description))
            print("Amount: "+ str(pay_req.num_satoshis))
            total_sent +=pay_req.num_satoshis

            yield request
        else:
            break


def start_paying():
    request_iterable = request_generator()
    time_prev = time.time()
    for payment in stub.SendPayment(request_iterable):
        time_now = time.time()
        elapsed = time_now-time_prev
        time_prev = time_now
        print(elapsed)
        print("Payment Error: '"+payment.payment_error+"'")

def welcome():
    print("--------------------------------------------------------------------------")
    print("                 Welcome to your Lightning Wallet")
    print("--------------------------------------------------------------------------")
    print("To start paying for a resource, enter the address of the resource device:")
    host = input("Host IP: ")
    port = int(input("Port IP: "))
    return host, port

def main():
    global sock

    host, port = welcome()

    #attempt to conect to socket on which resource device is listening
    connect_to_resource_socket(host, port)

    #start listening for invoices and paying them
    start_paying()

    #close socket connection
    sock.close()


if __name__ == "__main__":
    print("Started...")

    main()

    exit()
