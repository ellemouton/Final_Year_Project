'''
Imports and determine if running on Mac or RPi
'''
import platform
import sys
import time

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

time1 = []
time2 = []

def routing():

  print("----Route Mode----")

  #Symm key for A
  prev_hop = get_peer(peers, 'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7')
  prev_hop_channel = get_channel(prev_hop, channels)
  sym_key_prev_hop = prev_hop.sym_key

  while True:

      # receive header
      received_header = prev_hop.receive()

      t0 = time.time()

      decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())

      prev_hop.send(b'header ACK')

      #receive body
      encrypted_body = prev_hop.receive()

      #get header info
      commitment_tx_prev_hop = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
      secret_hash = check_htlc_and_get_secret_hash(node, commitment_tx_prev_hop, prev_hop_channel)
      cost_paid = route_cost(decrypted_header['route'], len(encrypted_body)-51)

      #adapt header and encrypt for next hop
      header = decrypted_header
      header['route'] = decrypted_header['route'][1:]
      cost_to_pay = route_cost(header['route'], len(encrypted_body)-51)

      next_hop = get_peer(peers, header['route'][0][0])
      next_hop_channel = get_channel(next_hop, channels)

      t1 = time.time()
      commitment_tx_next_hop = new_commitment_tx(node, next_hop_channel, cost_to_pay, secret_hash)
      t2 = time.time()

      header['commitment_tx'] = str(commitment_tx_next_hop.serialize().hex())

      sym_key_next_hop = next_hop.sym_key
      encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_next_hop.sec())

      t3 = time.time()

      #send header
      next_hop.send(encrypted_header)

      if(next_hop.receive()==b'header ACK'):
          next_hop.send(encrypted_body)

      reply = json.loads(next_hop.receive().decode())

      t4 = time.time()

      commitment_tx_next_hop = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
      revealed_secret = reply['secret']

      if(not (secret_hash == None) and (sha256(str.encode(revealed_secret)) == secret_hash)):
        #  print("I can sign the htlc output with the secret")

          next_hop_channel.pay(cost_to_pay)

          t5 = time.time()
          #sign the commitment tx
          z = commitment_tx_prev_hop.sig_hash(0)
          signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
          script_sig = commitment_tx_prev_hop.tx_ins[0].script_sig + Script([signature])
          commitment_tx_prev_hop.tx_ins[0].script_sig = script_sig
          t6 = time.time()

          reply = {"commitment_tx": str(commitment_tx_prev_hop.serialize().hex()), "secret": revealed_secret}

          prev_hop.send(str.encode(json.dumps(reply)))

          t7 = time.time()

          prev_hop_channel.paid(cost_paid)

          total = t7-t0
          print("Total: %.10f"%total)
          print("%.10f"%((t1-t0)*100/total))
          print("%.10f"%((t2-t1)*100/total))
          print("%.10f"%((t3-t2)*100/total))
          print("%.10f"%((t4-t3)*100/total))
          print("%.10f"%((t5-t4)*100/total))
          print("%.10f"%((t6-t5)*100/total))
          print("%.10f"%((t7-t6)*100/total))

          print("-------------------------")

      else:
          print("Cannot unlock HTLC")



routing()
