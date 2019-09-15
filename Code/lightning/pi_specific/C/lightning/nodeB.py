from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
from helper import sha256
import json

global peers

host = '127.0.0.1'
port = 2000

peers = []
channels = []

#portNumber = 2000

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeB')
print("Node Bitcoin Address: "+str(node.address))


while True:
  print("Options: \n1. Add peer\n2. Listen for peer\n3. Add Channel\n4. Listen for channel\n5. Route Mode")
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
    print("----Listen for peer----")
    print("Listening on: "+host+":"+str(port)+".....")
    
    peers.append(listen_for_new_peer(host, port, node))
    port+=1

    for p in peers:
      print(p)

  elif(user_option==3):
    print("----Add Channel----")
    print("Peers:")

    for i in range(len(peers)):
      print(str(i)+": "+str(peers[i]))

    peer_index = int(input("Enter peer index: "))
    channel_capacity = int(input("Enter channel capacity: "))

    channels.append(add_channel(peers[peer_index], channel_capacity))

    for c in channels:
      print(c)

  elif(user_option==4):
    print("----Listen for Channel request----")

    print("Peers:")

    for i in range(len(peers)):
      print(str(i)+": "+str(peers[i]))

    peer_index = int(input("Enter peer index: "))
    channels.append(listen_for_channel_request(peers[peer_index]))

    for c in channels:
      print(c)


  elif(user_option==5):
    print("----Route Mode----")

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






