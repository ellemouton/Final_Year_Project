import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os
from time import sleep

# Due to updated ECDSA generated tls.cert we need to let gprc know that
# we need to use that cipher suite otherwise there will be a handhsake
# error when we communicate with the lnd rpc server.
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'

# Lnd cert is at ~/.lnd/tls.cert on Linux and
# ~/Library/Application Support/Lnd/tls.cert on Mac
cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
creds = grpc.ssl_channel_credentials(cert)
channel = grpc.secure_channel('localhost:10002', creds)
stub = lnrpc.LightningStub(channel)


count = 1
create = input("Start? (y/n) ")

if(create=='y'):
    while True:
        #amount = int(input("Amount in satoshis: "))

        amount = count
        memo = "Payment number: "+str(count)

        print("---------------generating new invoice--------------")

        print("Amount:(sat) "+str(count))

        response = stub.AddInvoice(ln.Invoice(value=amount, memo=memo))

        f = open('interface.txt','w')
        f.write(response.payment_request)
        f.close()
        count+=1
        sleep(1)
        print("---------------------------------------------------")



