from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256
import secrets
import json

global peers


peers = []
channels = []


#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

'''
Automatically connect to peers C and B and D
'''
peers.append(connect_peer('127.0.0.1', 3002, node))
peers.append(connect_peer('127.0.0.1', 2000, node))
peers.append(connect_peer('127.0.0.1', 4000, node))

for p in peers:
  print(p)

'''
Automatically connect channel with B and D
'''
channels.append(add_channel(peers[1], 1000))
channels.append(add_channel(peers[2], 1000))

for c in channels:
  print(c)

print("----Send Mode----")

# destination (C's address (or rather, the Gateways BTC address))
destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'

while True:
  
  # find routes
  routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', get_price('mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn')], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', get_price('n1weDdde5xXLfPeutESLaG8swr5jLCqz72')]],
            [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', get_price('mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW')], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', get_price('n1weDdde5xXLfPeutESLaG8swr5jLCqz72')]]]

  # Find cost of each route and choose cheapest
  cheap_route_index = find_cheapest_route(routes)
  cheapest_route = routes[cheap_route_index]
  print(cheapest_route)
  cost = route_cost(cheapest_route)
  
  #body: secret and actual message -> encrypt for destination 
  secret = secrets.token_urlsafe(16)
  message = secrets.token_urlsafe(64)
  body = {"secret":secret, "message":message}
  sym_key_2 = node.secret*get_peer(peers, destination).public_key
  encrypted_body = encrypt(str.encode(json.dumps(body)), sym_key_2.sec())

  #header: source, route, secret hash -> encrypt for next hop
  header = {"source":node.address, "route": cheapest_route, "secret_hash": str(sha256(str.encode(secret)))}
  sym_key_1 = node.secret*get_peer(peers, cheapest_route[0][0]).public_key
  encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_1.sec())

  #send to next hop and wait for secret to be revealed
  next_hop = get_peer(peers, header['route'][0][0])

  #send header
  next_hop.send(encrypted_header)

  if(next_hop.receive()==b'header ACK'):
    next_hop.send(encrypted_body)
  
  revealed_secret = next_hop.receive()
  
  if(revealed_secret == str.encode(secret)):
    print("Successful delivery of message proven. Thus update channel state")
    get_channel(next_hop, channels).pay(cost)
    print(get_channel(next_hop, channels))

    print("Total Balance: "+str(get_total_channel_balance(channels)))

































