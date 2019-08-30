from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
from helper import sha256
import json

global peers

host = '127.0.0.1'
port = 4000

peers = []
channels = []

'''
create BTC address. secret -> private key -> public key
'''
node = BTC_node(b'nodeD')
print("Node Bitcoin Address: "+str(node.address))

'''
Get D's wallet transaction
'''
input_tx_id = 'e49a74f9b24d75b8e168b90b0d3eb930d11b3a387a2380343f159431bbb43d62'
input_tx_index = 0

'''
advertise price
'''
prices = json.load(open("peer_prices.txt"))
prices[node.address] = 3
json.dump(prices, open("peer_prices.txt",'w'))

'''
Automatically connect to peers C
'''
peers.append(connect_peer('127.0.0.1', 3001, node))

'''
Automatically listen for peer A
'''
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

'''
Automatically connect channel with C
'''
channels.append(add_channel(node, peers[0], input_tx_id, input_tx_index))

'''
Automatically listen for channels from A
'''
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)



print("----Route Mode----")
'''
while True:
  prev_hop = get_peer(peers, 'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7')
  sym_key_1 = node.secret*prev_hop.public_key

  # receive header
  received_header = prev_hop.receive()
  decrypted_header = json.loads(decrypt(received_header, sym_key_1.sec()).decode())

  prev_hop.send(b'header ACK')

  #receive body
  encrypted_body = prev_hop.receive()


  #adapt header and encrypt for next hop
  header = decrypted_header
  cost_paid = route_cost(header['route'])
  header['route'] = decrypted_header['route'][1:]
  cost_to_pay = route_cost(header['route'])
  sym_key_2 = node.secret*get_peer(peers, header['route'][0][0]).public_key
  encrypted_header = encrypt(str.encode(json.dumps(header)), sym_key_2.sec())
  secret_hash = header['secret_hash']
  
  #send to next hop and wait for secret to be revealed
  next_hop = get_peer(peers, header['route'][0][0])
  
  #send header
  next_hop.send(encrypted_header)
  
  if(next_hop.receive()==b'header ACK'):
    print("routing "+str(len(encrypted_body))+" bytes")
    next_hop.send(encrypted_body)
  
  revealed_secret = next_hop.receive()
  
  if(str(sha256(revealed_secret)) == secret_hash):
    get_channel(next_hop, channels).pay(cost_to_pay)
    print("Successful delivery of message proven. Thus update channel state")

    prev_hop.send(revealed_secret)
    get_channel(prev_hop, channels).paid(cost_paid)

    for c in channels:
      print(c)

    print("Total Balance: "+str(get_total_channel_balance(channels)))
'''





