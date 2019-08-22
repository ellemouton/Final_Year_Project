from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point

global peers


peers = []
channels = []


#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

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
      print(str(i)+": "+str(p))

    peer_index = int(input("Enter peer index: "))
    channel_capacity = int(input("Enter channel capacity: "))

    channels.append(add_channel(peers[peer_index], channel_capacity))

    for c in channels:
      print(c)

  elif(user_option==3):
    #Send message
    print("----Send Message----")




#add peer
input("Connect to peer on 127.0.0.1:2000?")
connect_peer('127.0.0.1', 2000)
print(peers[0])

#request channel
input("Initiate channel with this peer?")
add_channel(peers[0], 1000)
print(channels[0])

input("Send message to this peer and pay them 10 sat?")
#create message and encode message using node B's public key
message = b'Testing testing'
sym_key = nodeA.secret*peers[0].public_key
encrypted_message = encrypt(message, sym_key.sec())
peers[0].send(encrypted_message)

#wait to see if B can produce the origional message. 
decrypted_message = peers[0].receive()
if(decrypted_message == message):
  print("Successful delivery of message proven. Thus update channel state")

channels[0].pay(10)
print(channels[0])

peers[0].socket.close()

































