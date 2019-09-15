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
port = 2000
node_price = 2

def check_htlc(commitment_tx, secret):

    tx_in = TxIn(bytes.fromhex(commitment_tx.id()), 2)
    tx_out = TxOut(amount = commitment_tx.tx_outs[2].amount, script_pubkey = commitment_tx.tx_outs[0].script_pubkey)
    spendingTx = Tx(1, [tx_in], [tx_out], 0, True)

    z = spendingTx.sig_hash(0)
    signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
    combined = Script([signature, node.public_key.sec(), str.encode(secret), b'1']) + commitment_tx.tx_outs[2].script_pubkey
    
    return combined.evaluate(z, None)

def check_htlc_and_get_secret_hash(commitment_tx, channel):
    tx_in = commitment_tx.tx_ins[0]
    tx_out_1 = commitment_tx.tx_outs[1]
    tx_out_2 = commitment_tx.tx_outs[2]
    
    if(tx_in.prev_tx.hex() ==  channel.funding_tx.id()):
        if(tx_out_1.script_pubkey.cmds[2] == decode_base58(node.address) and tx_out_1.amount == channel.local_amt):
            if(tx_out_2.script_pubkey.cmds[6] == hash160(node.public_key.sec())):
                return tx_out_2.script_pubkey.cmds[2]
    return None  




# create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeB')
print("Node Bitcoin Address: "+str(node.address))

# Get B's wallet transaction
input_tx_id = '77535a39b5397a851539d4381ce3000bb5932ef6d7857e9c6e3e1aed6dd43216'
input_tx_index = 0

# advertise price
prices = json.load(open("peer_prices.txt"))
prices[node.address] = node_price
json.dump(prices, open("peer_prices.txt",'w'))

# Automatically connect to peers C
peers.append(connect_peer('127.0.0.1', 3000, node))

# Automatically listen for peer A
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

# Automatically connect channel with C
channels.append(add_channel(node, peers[0], input_tx_id, input_tx_index))

# Automatically listen for channels from A
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)


print("----Route Mode----")

prev_hop = get_peer(peers, 'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7')
prev_hop_channel = get_channel(prev_hop, channels)
sym_key_prev_hop = node.secret*prev_hop.public_key

while True:

    # receive header
    received_header = prev_hop.receive()
    decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())

    prev_hop.send(b'header ACK')

    #receive body
    encrypted_body = prev_hop.receive()

    #get header info
    commitment_tx_prev_hop = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
    secret_hash = check_htlc_and_get_secret_hash(commitment_tx_prev_hop, prev_hop_channel)
    print(len(encrypted_body))
    cost_paid = route_cost(decrypted_header['route'], len(encrypted_body))

    #adapt header and encrypt for next hop
    header = decrypted_header
    header['route'] = decrypted_header['route'][1:]
    cost_to_pay = route_cost(header['route'], len(encrypted_body))

    next_hop = get_peer(peers, header['route'][0][0])
    next_hop_channel = get_channel(next_hop, channels)

    commitment_tx_next_hop = new_commitment_tx(node, next_hop_channel, cost_to_pay, secret_hash)
    header['commitment_tx'] = str(commitment_tx_next_hop.serialize().hex())

    sym_key_next_hop = node.secret*next_hop.public_key
    encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_next_hop.sec())

    #send header
    next_hop.send(encrypted_header)

    if(next_hop.receive()==b'header ACK'):
        print("routing "+str(len(encrypted_body))+" bytes")
        next_hop.send(encrypted_body)

    reply = json.loads(next_hop.receive().decode())
    commitment_tx_next_hop = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
    revealed_secret = reply['secret']

    if(check_htlc(commitment_tx_prev_hop, revealed_secret)):
        print("I can sign the htlc output with the secret")

        next_hop_channel.pay(cost_to_pay)

        #sign the commitment tx
        z = commitment_tx_prev_hop.sig_hash(0)
        signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
        script_sig = commitment_tx_prev_hop.tx_ins[0].script_sig + Script([signature])
        commitment_tx_prev_hop.tx_ins[0].script_sig = script_sig

        reply = {"commitment_tx": str(commitment_tx_prev_hop.serialize().hex()), "secret": revealed_secret}

        prev_hop.send(str.encode(json.dumps(reply)))

        prev_hop_channel.paid(cost_paid)
        
        for c in channels:
          print(c)

        print("Total Balance: "+str(get_total_channel_balance(channels)))

    else:
        print("Cannot unlock HTLC")



