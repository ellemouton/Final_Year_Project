import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
import os

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



create = input("Create new invoice? (y/n) ")

if(create=='y'):
    amount = int(input("Amount in satoshis: "))
    memo = input("Memo for this invoice: ")

    print("---------------generating new invoice--------------")

    response = stub.AddInvoice(ln.Invoice(value=amount, memo=memo))

    print("Payment Request: "+str(response.payment_request))

    print("---------------------------------------------------")