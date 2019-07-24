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


def request_generator(dest, amt):
    counter=0
    print("Starting up")
    while True:
        request = ln.SendRequest(
                dest = dest,
                amt = amt,
        )
        yield request
        counter+=1
        sleep(2)


dest_hex = '034dc220edc18a110ae3165617d56ae8cc886f41dd167f45caffcbd1e3c066a258'
dest_bytes = codecs.decode(dest_hex, 'hex')

request_iterable = request_generator(dest=dest_bytes, amt=100)

for payment in stub.SendPayment(request_iterable):
        print(payment)
