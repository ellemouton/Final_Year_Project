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
import tkinter as tk
import shamir

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


'''
GUI
'''

global price_sock
global price


def sock_checker(node_address):
    global total_bytes_received_main

    prev_hop = get_peer(peers, node_address)
    current_channel = get_channel(prev_hop, channels)
    sym_key_prev_hop = prev_hop.sym_key

    while True:

        # receive header
        received_header = json.loads((prev_hop.receive()).decode())
        source = get_peer(peers, received_header['source'])
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(received_header['commitment_tx'])))
        H = check_htlc_and_get_secret_hash(node, commitment_tx, current_channel)
        num_packets = received_header['num_packets']
        packet_sizes = received_header['packet_size']
        prev_hop.send(b'header ACK')

        #receive packets
        packet_payloads = []
        for i in range(num_packets):
          packet_payloads.append(prev_hop.receive())
          prev_hop.send(b'packet ACK')

        #decode packets
        sym_key_source = source.sym_key
        decoded_packets = []
        for i in range(len(packet_payloads)):
          print('------------')
          print(packet_payloads[i])
          print('------------')
          print(sym_key_source.sec())
          decoded_packets.append(json.loads(decrypt(packet_payloads[i], sym_key_source.sec()).decode()))

        #get the shares
        shares = []
        for i in range(len(decoded_packets)):
          shamir_share = decoded_packets[i]['secret_share']
          x, y = map(int, shamir_share.strip('()').split(','))
          shares.append((x,y))


        revealed_secret = shamir.recover_secret(shares)

        #check that you can suceesfully unlock the htlc output
        if(not (H == None) and (sha256(str.encode(str(revealed_secret))) == H)):
            print("I can sign the htlc output with the secret")

            #sign the commitment tx
            commitment_tx.tx_ins[0].script_sig = get_script_sig(commitment_tx, node.private_key)

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


sockB = threading.Thread(target = sock_checker, kwargs = dict(node_address = 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'))
sockB.start()

sockD = threading.Thread(target = sock_checker, kwargs = dict(node_address = 'mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'))
sockD.start()

