from socket_helper import SocketError, SocketClient
from general_helper import Peer, Channel, create_btc_address, encrypt, BTC_node
from time import sleep
from ecc import S256Point

global peers

def connect_peer(host, port):
  global peers
  global nodeA

  sock = SocketClient(host, port)
  if(sock.connect()):

    peer_address =  sock.receive()
    peer_pub_key = sock.receive()

    sock.send(str.encode(nodeA.address))
    sock.send(nodeA.public_key.sec())

    pub_key = S256Point.parse(peer_pub_key)

    peers.append(Peer(sock, peer_address, pub_key))
    print("new peer added")
    return True

  return False

def add_channel(peer, local_amt, remote_amt=0):
  global channels

  #send channel request
  new_channel = Channel(peer, local_amt, remote_amt)
  peer.send(str.encode(new_channel.toJSON()))

  #receive approval from peer and add new channel
  if(peer.receive() == b'approved'):
    channels.append(new_channel)
    return True
  else:
    print("Channel Request declined")
    return False


peers = []
channels = []

#create BTC address. secret -> private key -> public key
nodeA = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(nodeA.address))

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

































