import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os
from time import sleep
import codecs

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

# Lnd cert is at ~/.lnd/tls.cert on Linux and
# ~/Library/Application Support/Lnd/tls.cert on Mac
cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10001', creds)
stub = lnrpc.LightningStub(channel)

global content

def readFile():
    global content
    file = open('interface.txt', 'r+')
    content = file.read()
    if len(content)>0:
        file.truncate(0)
        file.close()
        return True
    return False

def request_generator():
    global content

    print("Starting up")

    while True:

        if readFile():
            request = ln.SendRequest(payment_request=content)

            print("--------New Payment Details---------")
            pay_req = stub.DecodePayReq(ln.PayReqString(pay_req = content))
            print("Memo: "+str(pay_req.description))
            print("Amount: "+ str(pay_req.num_satoshis))
            yield request


request_iterable = request_generator()

for payment in stub.SendPayment(request_iterable):
    print("Payment Error: '"+payment.payment_error+"'")
