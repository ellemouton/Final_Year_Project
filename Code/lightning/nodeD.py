from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
import json

global peers

host = '127.0.0.1'
port = 4000

peers = []
channels = []

#portNumber = 2000

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeD')
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
    #Send message
    print("----Route Mode----")






