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
      print(str(i)+": "+str(p))

    peer_index = int(input("Enter peer index: "))
    channels.append(listen_for_channel_request(peers[peer_index]))

    for c in channels:
      print(c)

  elif(user_option==3):
    #Send message
    print("----Receive Mode----")
