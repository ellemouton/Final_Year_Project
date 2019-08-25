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
print(node.public_key.sec())

#add gateway info as a peer
peers.append(Peer(None, b'n1weDdde5xXLfPeutESLaG8swr5jLCqz72', S256Point.parse(b'\x03C\xc7\xe7\x87e\xe6\xcf\x07\xefN\x84\xfd\xc4\x07&\x97&?\xdd\xed\xd7F3\xe6(\xe2\xa1];\x85\nt')))


while True:
  print("Options: \n1. Add peer\n2. Create channel\n3. Send Message")
  user_option = int(input("Option number: "))

  
  if(user_option==1):
    print("----Add Peer----")
    #peer_host = input("Peer Host: ")
    peer_host = '127.0.0.1'
    peer_port = int(input("Peer Port: "))
    peers.append(connect_peer(peer_host, peer_port, node))

    for p in peers:
      print(p)

  elif(user_option==2):
    print("----Create Channel----")

    print("Peers:")

    for i in range(len(peers)):
      print(str(i)+": "+str(peers[i]))

    peer_index = int(input("Enter peer index: "))
    channel_capacity = int(input("Enter channel capacity: "))

    channels.append(add_channel(peers[peer_index], channel_capacity))

    for c in channels:
      print(c)

  elif(user_option==3):
    #Send message
    print("----Send Message----")

    while True:
      # destination (C's address (or rather, the Gateways BTC address))
      destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'

      # find routes
      routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', 1], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', 2]],
                [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', 6], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', 2]]]

      # Find cost of each route and choose cheapest
      cheap_route_index = find_cheapest_route(routes)
      cheapest_route = routes[cheap_route_index]
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

































