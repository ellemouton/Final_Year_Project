from socket_helper import SocketError, SocketServer
from general_helper import Peer, Channel, create_btc_address, decrypt, BTC_node
from time import sleep 
from ecc import S256Point
import json

global peers

def listen_for_new_peer(host, port):
  global peers
  global nodeB

  sock = SocketServer(host, port)
  sock.listen()

  sock.send(str.encode(nodeB.address))
  sock.send(nodeB.public_key.sec())

  peer_address = sock.receive()
  peer_pub_key = sock.receive()

  pub_key = S256Point.parse(peer_pub_key)

  peers.append(Peer(sock, peer_address, pub_key))
  print("new peer added")


def listen_for_channel_request(peer):
  global channels

  request = json.loads(peer.receive())

  print(request)
  input("Aprove Channel?")

  peer.send(b'approved')

  new_channel = Channel(peer, request['remote_amt'], request['local_amt'])
  channels.append(new_channel)
  print("channel added")


peers = []
channels = []

#create BTC address. secret -> private key -> public key
nodeB = BTC_node(b'nodeB')
print("Node Bitcoin Address: "+str(nodeB.address))

#accept peer
input("Listen for new peer on port 2000?")
listen_for_new_peer('127.0.0.1', 2000)
print(peers[0])

#accept channel
input("Listen for new channel request on port 2000?")
listen_for_channel_request(peers[0])
print(channels[0])


#receive encrypted message
encrypted_message = peers[0].receive()
sym_key = nodeB.secret*peers[0].public_key
decrypted_message = decrypt(encrypted_message, sym_key.sec())
print(decrypted_message)

#send decrypted message back to A
peers[0].send(decrypted_message)

#Update payment channel 
channels[0].paid(10)
print(channels[0])



#peers[0].socket.close()















































