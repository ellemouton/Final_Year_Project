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
channel = grpc.secure_channel('localhost:10003', creds)
stub = lnrpc.LightningStub(channel)

invoice_states = ["OPEN", "SETTLED", "CANCELED", "ACCEPTED"]

request = ln.InvoiceSubscription()

total = 0
print("Total Satoshis Received: "+str(total))

for invoice in stub.SubscribeInvoices(request):
    print("---------Latest------------")
    print("Memo: "+str(invoice.memo))
    print("Value: "+str(invoice.value))
    print("Payment_request: "+str(invoice.payment_request))
    print("STATE: "+invoice_states[invoice.state])
    print("---------------------------")

    if(invoice.state==1):
        total += invoice.value
        print("Total Satoshis Recieved: "+str(total))
