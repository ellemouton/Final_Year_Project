from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import json
import threading

global peers

peers = []
channels = []

host = '127.0.0.1'
port = 3000
node_price = 2

def check_htlc(commitment_tx, secret):

    tx_in = TxIn(bytes.fromhex(commitment_tx.id()), 2)
    tx_out = TxOut(amount = commitment_tx.tx_outs[2].amount, script_pubkey = commitment_tx.tx_outs[0].script_pubkey)
    spendingTx = Tx(1, [tx_in], [tx_out], 0, True)

    z = spendingTx.sig_hash(0)
    signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
    combined = Script([signature, node.public_key.sec(), str.encode(secret), b'1']) + commitment_tx.tx_outs[2].script_pubkey
    
    return combined.evaluate(z, None)


def sockB_checker():
    prev_hop = get_peer(peers, 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn')
    current_channel = get_channel(prev_hop, channels)
    sym_key_prev_hop = node.secret*prev_hop.public_key

    while True:

        # receive header
        received_header = prev_hop.receive()
        decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())
        source = get_peer(peers, decrypted_header['source'])
        cost_paid = route_cost(decrypted_header['route'])
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
        prev_hop.send(b'header ACK')

        #receive body
        sym_key_source = node.secret*source.public_key
        encrypted_body = prev_hop.receive()
        decrypted_message = json.loads(decrypt(encrypted_body, sym_key_source.sec()).decode())
        secret = decrypted_message['secret']

        #check that you can suceesfully unlock the htlc output
        if(check_htlc(commitment_tx, secret)):
            print("I can sign the htlc output with the secret")

            #sign the commitment tx
            z = commitment_tx.sig_hash(0)
            signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
            script_sig = commitment_tx.tx_ins[0].script_sig + Script([signature])
            commitment_tx.tx_ins[0].script_sig = script_sig

            reply = {"commitment_tx": str(commitment_tx.serialize().hex()), "secret": secret}

            prev_hop.send(str.encode(json.dumps(reply)))

            current_channel.paid(commitment_tx.tx_outs[2].amount)
            print(current_channel)
            print("Total Balance: "+str(get_total_channel_balance(channels)))

        else:
            print("Cannot unlock HTLC")

def sockD_checker():
    prev_hop = get_peer(peers, 'mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW')
    current_channel = get_channel(prev_hop, channels)
    sym_key_prev_hop = node.secret*prev_hop.public_key

    while True:

        # receive header
        received_header = prev_hop.receive()
        decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())
        source = get_peer(peers, decrypted_header['source'])
        cost_paid = route_cost(decrypted_header['route'])
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
        prev_hop.send(b'header ACK')

        #receive body
        sym_key_source = node.secret*source.public_key
        encrypted_body = prev_hop.receive()
        decrypted_message = json.loads(decrypt(encrypted_body, sym_key_source.sec()).decode())
        secret = decrypted_message['secret']

        #check that you can suceesfully unlock the htlc output
        if(check_htlc(commitment_tx, secret)):
            print("I can sign the htlc output with the secret")

            #sign the commitment tx
            z = commitment_tx.sig_hash(0)
            signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
            script_sig = commitment_tx.tx_ins[0].script_sig + Script([signature])
            commitment_tx.tx_ins[0].script_sig = script_sig

            reply = {"commitment_tx": str(commitment_tx.serialize().hex()), "secret": secret}

            prev_hop.send(str.encode(json.dumps(reply)))

            current_channel.paid(commitment_tx.tx_outs[2].amount)
            print(current_channel)
            print("Total Balance: "+str(get_total_channel_balance(channels)))

        else:
            print("Cannot unlock HTLC")

'''
create BTC address. secret -> private key -> public key
'''
node = BTC_node(b'nodeC')
print("Node Bitcoin Address: "+str(node.address))

'''
advertise price
'''
prices = json.load(open("peer_prices.txt"))
prices[node.address] = node_price
json.dump(prices, open("peer_prices.txt",'w'))

'''
Automatically listen for peers A, B and D
'''
# peer B
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer D
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer A
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

'''
Automatically listen for channels from B and D
'''
channels.append(listen_for_channel_request(peers[0]))
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)

print("----Receive Mode----")

sockB = threading.Thread(target=sockB_checker)
sockB.start()

sockD = threading.Thread(target=sockD_checker)
sockD.start()


