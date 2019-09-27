''' 
Imports and determine if running on Mac or RPi
'''
import platform
import sys

global system

if(platform.platform()[0:3]=="Lin"):
  system = 0 #RPi
  sys.path.insert(0, '/home/pi/Documents/final/modules')
else:
  system = 1 #Mac
  sys.path.insert(0, '/Users/ellemouton/Documents/2019/Sem2/EEE4022S/Code/lightning/modules')

from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import secrets
import json
import threading

'''
      Set up node, peers and channels
'''
global host

peers = []
channels = []

if(system==0):
  host = '169.254.10.3'
else:
  host = '127.0.0.1'

port = 3000

def sock_checker(node_address):
    global total_bytes_received_main

    prev_hop = get_peer(peers, node_address)
    current_channel = get_channel(prev_hop, channels)
    sym_key_prev_hop = prev_hop.sym_key

    while True:

        # receive header
        received_header = prev_hop.receive()
        decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())
        source = get_peer(peers, decrypted_header['source'])
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
        secret_hash = check_htlc_and_get_secret_hash(node, commitment_tx, current_channel)
        prev_hop.send(b'header ACK')

        #receive body
        sym_key_source = source.sym_key
        encrypted_body = prev_hop.receive()
        decrypted_message = json.loads(decrypt(encrypted_body, sym_key_source.sec()).decode())
        revealed_secret = decrypted_message['secret']
        #cost_paid = route_cost(decrypted_header['route'], len(encrypted_body))

        #check that you can suceesfully unlock the htlc output
        if(not (secret_hash == None) and (sha256(str.encode(revealed_secret)) == secret_hash)):
            print("I can sign the htlc output with the secret")

            #sign the commitment tx
            z = commitment_tx.sig_hash(0)
            signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
            script_sig = commitment_tx.tx_ins[0].script_sig + Script([signature])
            commitment_tx.tx_ins[0].script_sig = script_sig

            reply = {"commitment_tx": str(commitment_tx.serialize().hex()), "secret": revealed_secret}

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
Automatically listen for peers A, B and D
'''
# peer B
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

for c in channels:
  print(c)

print("----Receive Mode----")


sockB = threading.Thread(target = sock_checker, kwargs = dict(node_address = 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'))
sockB.start()

