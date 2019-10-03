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

from socket_helper import SocketError, SocketClient, SocketServer
import tkinter as tk
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
global host_C
global channels

total_bytes_routed_main = 0

peers = []
channels = []

if(system==0):
  host = '169.254.10.1'
  host_C = '169.254.10.3'
else:
  host = '127.0.0.1'
  host_C = '127.0.0.1'

port = 2000


# create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeB')
print("Node Bitcoin Address: "+str(node.address))

evil = False

# Get B's wallet transaction
input_tx_id = '77535a39b5397a851539d4381ce3000bb5932ef6d7857e9c6e3e1aed6dd43216'
input_tx_index = 0

# Automatically connect to peers C
peers.append(connect_peer(host_C, 3000, node))

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


def routing():

  print("----Route Mode----")

  #Symm key for A
  prev_hop = get_peer(peers, 'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7')
  prev_hop_channel = get_channel(prev_hop, channels)
  sym_key_prev_hop = prev_hop.sym_key

  while True:
      received_header = json.loads((prev_hop.receive()).decode())

      #get header info
      commitment_tx_prev_hop = Tx.parse(BytesIO(bytes.fromhex(received_header['commitment_tx'])))
      H = check_htlc_and_get_secret_hash(node, commitment_tx_prev_hop, prev_hop_channel)
      num_packets = received_header['num_packets']
      packet_sizes = received_header['packet_size']

      prev_hop.send(b'header ACK')

      packet_payloads = []
      for i in range(num_packets):
        packet_payloads.append(prev_hop.receive())
        prev_hop.send(b'packet ACK')

      cost_paid = int(route_cost(received_header['route'], num_packets*packet_sizes))

      #adapt header and encrypt for next hop
      header = received_header
      header['route'] = received_header['route'][1:]
      cost_to_pay = int(route_cost(header['route'], num_packets*packet_sizes))
      #print("cost_to_pay: "+str(cost_to_pay))

      next_hop = get_peer(peers, header['route'][0][0])
      next_hop_channel = get_channel(next_hop, channels)

      #new commitment
      commitment_tx_next_hop = new_commitment_tx(node, next_hop_channel, cost_to_pay, H)
      header['commitment_tx'] = str(commitment_tx_next_hop.serialize().hex())

      #send header
      next_hop.send(str.encode(json.dumps(header)))

      if(next_hop.receive()==b'header ACK'):

          for i in range(num_packets):
            next_hop.send(packet_payloads[i])
            next_hop.receive()


      reply = json.loads(next_hop.receive().decode())
      commitment_tx_next_hop = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
      revealed_secret = reply['secret']

      if(not (H == None) and (sha256(str.encode(str(revealed_secret))) == H)):
          #print("I can sign the htlc output with the secret")

          next_hop_channel.pay(cost_to_pay)

          #sign the commitment tx
          commitment_tx_prev_hop.tx_ins[0].script_sig = get_script_sig(commitment_tx_prev_hop, node.private_key)

          reply = {"commitment_tx": str(commitment_tx_prev_hop.serialize().hex()), "secret": revealed_secret}

          prev_hop.send(str.encode(json.dumps(reply)))

          prev_hop_channel.paid(cost_paid)

          #for c in channels:
          #  print(c)

          wallet_balance = get_total_channel_balance(channels)

          #print("Total Balance: "+str(wallet_balance))

      else:
          print("Cannot unlock HTLC")


route = threading.Thread(target = routing)
route.start()

