import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os
from time import sleep
import codecs
import socket

os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10001', creds)
stub = lnrpc.LightningStub(channel)

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

global content

def readFile():
    global content

    content = s.recv(1024)
    if len(content)>0:
        return True
    return False

def request_generator():
    global content

    total_sent = 0

    print("Starting up")

    while True:

        if readFile():
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


request_iterable = request_generator()

for payment in stub.SendPayment(request_iterable):
    print("Payment Error: '"+payment.payment_error+"'")
s.close()
