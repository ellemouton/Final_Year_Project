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

from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import secrets
import json

'''
      #Set up node, peers and channels
'''
global host
global host_C
global host_B
global host_D

peers = []
channels = []

prices = {"n1weDdde5xXLfPeutESLaG8swr5jLCqz72": 1, "mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn": 1, "mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW": 1}


#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

#Get A's wallet transaction
input_tx_id = 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
input_tx_index = 1

#Automatically connect to peers C and B and D
if(system==0):
  host_C = '169.254.10.3'
  host_B = '169.254.10.1'
else:
  host_C = '127.0.0.1'
  host_B = '127.0.0.1'

peers.append(connect_peer(host_C, 3001, node))
peers.append(connect_peer(host_B, 2000, node))

for p in peers:
  print(p)

#Automatically connect channel with B and D
channels.append(add_channel(node, peers[1], input_tx_id, input_tx_index))

for c in channels:
  print(c)


'''
 Start Sending Packets
'''

print("----Send Mode----")

def send_packets():
  global packet_size_main

  # destination (C's address (or rather, the Gateways BTC address))
  destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'
  sym_key_dest = get_peer(peers, destination).sym_key

  while True:
    
    packet_size_main = int(input("Num bytes: "))

    if(packet_size_main>0):
      # find routes
      routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]],
                [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]]]

      # Find cost of each route and choose cheapest
      cheap_route_index = find_cheapest_route(routes)
      cheapest_route = routes[cheap_route_index]
      
      # get next hop from route and hence get relevent channel
      next_hop = get_peer(peers, routes[cheap_route_index][0][0])
      next_hop_channel = get_channel(next_hop, channels)

      #body: secret and actual message -> encrypt for destination 
      secret = secrets.token_urlsafe(16)
      secret_hash = sha256(str.encode(secret))
      message = secrets.token_urlsafe(packet_size_main)
      body = {"secret":secret, "message":message}
      encrypted_body = encrypt(str.encode(json.dumps(body)), sym_key_dest.sec())
      cost = route_cost(cheapest_route, len(message))

      commitment_tx = new_commitment_tx(node, next_hop_channel, cost, secret_hash)

      # header: source, route, secret hash -> encrypt for next hop
      header = {"source":node.address, "route": cheapest_route, "commitment_tx": str(commitment_tx.serialize().hex())}
      sym_key_next_hop = get_peer(peers, cheapest_route[0][0]).sym_key
      encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_next_hop.sec())

      t0 = time.time()
      # send header
      next_hop.send(encrypted_header)

      # send body if header is accepted
      if(next_hop.receive()==b'header ACK'):
        next_hop.send(encrypted_body)
      
      reply = json.loads(next_hop.receive().decode())
      commitment_tx = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
      revealed_secret = reply['secret']
      
      if(revealed_secret == secret):
        t1 = time.time()
        total = t1-t0
        print("%.10f"%total)

        print("Successful delivery of message proven. Thus update channel state")

        next_hop_channel.pay(commitment_tx.tx_outs[2].amount)

        print(get_channel(next_hop, channels))
      

send_packets()








