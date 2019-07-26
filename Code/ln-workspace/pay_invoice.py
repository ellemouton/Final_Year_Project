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
channel = grpc.secure_channel('localhost:10001', creds)
stub = lnrpc.LightningStub(channel)

pay = input("Pay an invoice? (y/n): ")

if(pay=='y'):
    pay_req = input("Enter payement_request: ")

    decode_invoice = stub.DecodePayReq(ln.PayReqString(pay_req=pay_req))

    print("-------Confirm the following details---------")

    print("Destination: "+str(decode_invoice.destination))
    print("Amount (in sat): "+str(decode_invoice.num_satoshis))
    print("Description: "+str(decode_invoice.description))


    print("---------------------------------------------")

    if(input("Pay? (y/n): ")=="y"):
        response = stub.SendPaymentSync(ln.SendRequest(payment_request=pay_req))

