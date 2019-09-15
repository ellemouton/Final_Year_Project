from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import secrets
import json

global peers


def get_packet_size():
  return int(json.load(open("packet_size.txt"))['size'])

peers = []
channels = []

'''
create BTC address. secret -> private key -> public key
'''
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

'''
Get A's wallet transaction
'''
input_tx_id_1 = 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
input_tx_index_1 = 1

input_tx_id_2 = '15fccae87a15395af0232ba7e1a5659a6d3ca67c90ebdf900025753fb6a57f3e'
input_tx_index_2 = 0

'''
Automatically connect to peers C and B and D
'''
peers.append(connect_peer('169.254.10.3', 3002, node))
peers.append(connect_peer('169.254.10.1', 2000, node))
peers.append(connect_peer('169.254.10.10', 4000, node))

for p in peers:
  print(p)

'''
Automatically connect channel with B and D
'''
channels.append(add_channel(node, peers[1], input_tx_id_1, input_tx_index_1))
channels.append(add_channel(node, peers[2], input_tx_id_2, input_tx_index_2))

for c in channels:
  print(c)


print("----Send Mode----")

# destination (C's address (or rather, the Gateways BTC address))
destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'
sym_key_dest = node.secret*get_peer(peers, destination).public_key

while True:
  
  # find routes
  routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', get_price('mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn')], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', get_price('n1weDdde5xXLfPeutESLaG8swr5jLCqz72')]],
            [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', get_price('mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW')], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', get_price('n1weDdde5xXLfPeutESLaG8swr5jLCqz72')]]]

  # Find cost of each route and choose cheapest
  cheap_route_index = find_cheapest_route(routes)
  cheapest_route = routes[cheap_route_index]
  
  
  # get next hop from route and hence get relevent channel
  next_hop = get_peer(peers, routes[cheap_route_index][0][0])
  next_hop_channel = get_channel(next_hop, channels)

  #body: secret and actual message -> encrypt for destination 
  secret = secrets.token_urlsafe(16)
  secret_hash = sha256(str.encode(secret))
  message = secrets.token_urlsafe(get_packet_size())
  body = {"secret":secret, "message":message}
  encrypted_body = encrypt(str.encode(json.dumps(body)), sym_key_dest.sec())
  cost = route_cost(cheapest_route, len(encrypted_body))

  commitment_tx = new_commitment_tx(node, next_hop_channel, cost, secret_hash)

  # header: source, route, secret hash -> encrypt for next hop
  header = {"source":node.address, "route": cheapest_route, "commitment_tx": str(commitment_tx.serialize().hex())}
  sym_key_next_hop = node.secret*get_peer(peers, cheapest_route[0][0]).public_key
  encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_next_hop.sec())

  # send header
  next_hop.send(encrypted_header)

  # send body if header is accepted
  if(next_hop.receive()==b'header ACK'):
    next_hop.send(encrypted_body)
  
  reply = json.loads(next_hop.receive().decode())
  commitment_tx = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
  revealed_secret = reply['secret']
  
  if(revealed_secret == secret):
    print("Successful delivery of message proven. Thus update channel state")

    next_hop_channel.pay(commitment_tx.tx_outs[2].amount)

    print(get_channel(next_hop, channels))

    print("Total Balance: "+str(get_total_channel_balance(channels)))
  































