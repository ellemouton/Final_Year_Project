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
import time

global go
go = True
'''
      #Set up node, peers and channels
'''
global host
global host_C
global host_B

global packet_size_main
global current_packet_multiple
global total_bytes_sent_main
global total_sat_paid_main

prices = {"n1weDdde5xXLfPeutESLaG8swr5jLCqz72": 0.001, "mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn": 0.001, "mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW": 0.001}

peers =[]
channels =[]
packet_size_main = 0
current_packet_multiple = 7
total_bytes_sent_main = 0
total_sat_paid_main = 0

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

#Get A's wallet transaction
input_tx_id_1 = 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
input_tx_index_1 = 1


#Automatically connect to peers C and B and D
if(system==0):
  host_C = '169.254.10.3'
  host_B = '169.254.10.1'
  host_D = '169.254.10.10'
else:
  host_C = '127.0.0.1'
  host_B = '127.0.0.1'
  host_D = '127.0.0.1'

peers.append(connect_peer(host_C, 3001, node))
peers.append(connect_peer(host_B, 2000, node))

for p in peers:
  print(p)

#Automatically connect channel with B and D
channels.append(add_channel(node, peers[1], input_tx_id_1, input_tx_index_1))

for c in channels:
  print(c)

'''
 Start Sending Packets
'''

print("----Send Mode----")

def send_packets():
  global packet_size_main
  global total_bytes_sent_main
  global total_sat_paid_main
  global go

  size = 1000
  packet_numbers = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 260, 270, 280, 290, 300]
  times = []

  # destination (C's address (or rather, the Gateways BTC address))
  destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'
  sym_key_dest = get_peer(peers, destination).sym_key

  for n in packet_numbers:

    #get info from user
    packet_size_main = size
    num_packets = n
    

    if(packet_size_main>0 and num_packets>0):

      # find routes
      routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]],
                [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]]]

      t0 = time.time()
      #body: secret and actual message -> encrypt for destination
      X, shares = shamir.make_random_shares(num_packets, num_packets)
      H = sha256(str.encode(str(X)))

      packet_payloads = []

      for i in range(num_packets):
        message = secrets.token_urlsafe(packet_size_main)
        secret_share = str(shares[i])
        body = {"secret_share":secret_share, "message":message}
        encrypted_body = encrypt(str.encode(json.dumps(body)), sym_key_dest.sec())
        packet_payloads.append(encrypted_body)

      
      # Find cost of each route and choose cheapest
      cheap_route_index = find_cheapest_route(routes)
      cheapest_route = routes[cheap_route_index]

      # get next hop from route and hence get relevent channel
      next_hop = get_peer(peers, routes[cheap_route_index][0][0])
      next_hop_channel = get_channel(next_hop, channels)

      cost = int(route_cost(cheapest_route, packet_size_main*num_packets))

      #construct new commitment transaction
      commitment_tx = new_commitment_tx(node, next_hop_channel, cost, H)

      # header: source, route, secret hash -> encrypt for next hop
      header = {"source":node.address, "route": cheapest_route, "num_packets":num_packets, "packet_size": packet_size_main, "commitment_tx": str(commitment_tx.serialize().hex())}
    
      # send header
      next_hop.send(str.encode(json.dumps(header)))

      # send body if header is accepted
      if(next_hop.receive()==b'header ACK'):

        for i in range(num_packets):
          next_hop.send(packet_payloads[i])
          next_hop.receive()

      #receive and analyse reply

      reply = json.loads(next_hop.receive().decode())
      commitment_tx = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
      revealed_secret = reply['secret']

      if(revealed_secret == X):
        t1 = time.time()
        total = t1-t0
        times.append(total)
        print(total)

        print("Successful delivery of message proven. Thus update channel state")
        success = True

        next_hop_channel.pay(commitment_tx.tx_outs[2].amount)

        #print(get_channel(next_hop, channels))

        wallet_balance = get_total_channel_balance(channels)

        #print("Total Balance: "+str(wallet_balance))
        go = False

  fileName = 'results_5_.txt'
  with open(fileName, 'w') as f:
    f.truncate(0)

    for t in times:
        f.write('%.10f\n' % t)

send = threading.Thread(target = send_packets)
send.start()











