from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
import json

global peers

peers = []
channels = []

host = '127.0.0.1'
port = 3000

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeC')
print("Node Bitcoin Address: "+str(node.address))

peers.append(Peer(None, b'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7', S256Point.parse(b'\x03\xad\x999Q\xe9\xb6\xf5e%o\\i\x07\xfb\xd4,\x0f+\xf5\xdd_\x8051\xc9\xd0\xa6\xea\xcb\xfa\xba\x86')))

while True:
  print("Options: \n1. Listen for peer\n2. Listen for channel request\n3. Receive Mode")
  user_option = int(input("Option number: "))

  if(user_option==1):
    print("----Listen for peer----")
    print("Listening on: "+host+":"+str(port)+".....")
    
    peers.append(listen_for_new_peer(host, port, node))
    port+=1

    for p in peers:
      print(p)

  elif(user_option==2):
    print("----Listen for channel request----")

    print("Peers:")

    for i in range(len(peers)):
      print(str(i)+": "+str(peers[i]))

    peer_index = int(input("Enter peer index: "))
    channels.append(listen_for_channel_request(peers[peer_index]))

    for c in channels:
      print(c)

  elif(user_option==3):
    #Send message
    print("----Receive Mode----")

    while True:
      prev_hop = get_peer(peers, 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn')
      sym_key_1 = node.secret*prev_hop.public_key

      # receive header
      received_header = prev_hop.receive()
      decrypted_header = json.loads(decrypt(received_header, sym_key_1.sec()).decode())
      source = get_peer(peers, decrypted_header['source'])
      cost_paid = route_cost(decrypted_header['route'])

      prev_hop.send(b'header ACK')

      #receive body
      sym_key_2 = node.secret*source.public_key
      encrypted_body = prev_hop.receive()
      decrypted_message = json.loads(decrypt(encrypted_body, sym_key_2.sec()).decode())
      secret = decrypted_message['secret']

      prev_hop.send(str.encode(secret))
      get_channel(prev_hop, channels).paid(cost_paid)
      print(get_channel(prev_hop, channels))



