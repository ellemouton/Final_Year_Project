import json
from ecc import PrivateKey
from helper import hash256, little_endian_to_int
from socket_helper import SocketError, SocketServer, SocketClient
from ecc import S256Point
import sys

class BTC_node:
  def __init__(self, passphrase):
    self.secret = little_endian_to_int(hash256(passphrase))
    self.private_key = PrivateKey(self.secret)
    self.public_key = self.private_key.point
    self.address = self.public_key.address(testnet=True)

class Peer:
  def __init__(self, socket, btc_addr, public_key):
    self.socket = socket
    self.btc_addr = btc_addr
    self.public_key = public_key

  def send(self,data):
      self.socket.send(data)

  def receive(self,size=1024):
      return self.socket.receive(size)

  def __str__(self):
    return str(self.socket)+", peer btc address: "+str(self.btc_addr)

class Channel:
  def __init__(self, peer, local_amt, remote_amt):
    self.peer = peer
    self.local_amt = local_amt
    self.remote_amt = remote_amt

  def pay(self, amt):
    self.local_amt -=amt
    self.remote_amt +=amt

  def paid(self, amt):
    self.local_amt +=amt
    self.remote_amt -=amt

  def __str__(self):
    return str(self.peer.btc_addr)+", local balance: "+str(self.local_amt)+", remote balance: "+str(self.remote_amt)

  def toJSON(self):
    data = {}
    data['addr'] = self.peer.btc_addr.decode()
    data['local_amt'] = self.local_amt
    data['remote_amt'] = self.remote_amt
    return json.dumps(data)

def create_btc_address(passphrase):
  secret = little_endian_to_int(hash256(passphrase))
  publicKey = PrivateKey(secret).point
  print(publicKey.sec())
  address = publicKey.address(testnet=True)
  return address

def listen_for_new_peer(host, port, node):

  sock = SocketServer(host, port)
  sock.listen()

  sock.send(str.encode(node.address))
  peer_address = sock.receive()
  sock.send(node.public_key.sec())
  peer_pub_key = sock.receive()

  peer_pub_key_point = S256Point.parse(peer_pub_key)
  return Peer(sock, peer_address, peer_pub_key_point)

def connect_peer(host, port, node):

  sock = SocketClient(host, port)
  sock.connect()

  peer_address = sock.receive()
  sock.send(str.encode(node.address))
  peer_pub_key = sock.receive()
  sock.send(node.public_key.sec())

  peer_pub_key_point = S256Point.parse(peer_pub_key)

  return Peer(sock, peer_address, peer_pub_key_point)

def add_channel(peer, local_amt, remote_amt=0):

  #send channel request
  new_channel = Channel(peer, local_amt, remote_amt)
  peer.send(str.encode(new_channel.toJSON()))

  return new_channel

def listen_for_channel_request(peer):

  request = json.loads(peer.receive())

  new_channel = Channel(peer, request['remote_amt'], request['local_amt'])
  return new_channel

def find_cheapest_route(routes):
  costs = []

  for i in range(len(routes)):
    cost = 0
    for n in routes[i]:
      cost += n[1]
    costs.append(cost)
  return costs.index(min(costs))

def route_cost(route):
  cost = 0
  for n in route:
      cost += n[1]
  return cost

def get_peer(peers, btc_addr):
  for p in peers:
    if(p.btc_addr == str.encode(btc_addr)):
      return p
  return None

def route_to_string(route):
  path = []
  for r in route:
    path.append(r[0])
  return ", ".join(path)

def get_channel(peer, channels):
  for c in channels:
    if(peer == c.peer):
      return c
  return None

def get_price(btc_addr):
  prices = json.load(open("peer_prices.txt"))
  return prices[btc_addr]

def get_total_channel_balance(channels):
  local_balance = 0

  for c in channels:
    local_balance += c.local_amt
    
  return local_balance


def xor(var, key):
  while(len(key)<len(var)):
    key += key
  key = key[:len(var)]
  int_var = int.from_bytes(var, sys.byteorder)
  int_key = int.from_bytes(key, sys.byteorder)
  int_enc = int_var ^ int_key
  return int_enc.to_bytes(len(var), sys.byteorder)

def encrypt(message, key):
  return xor(message, key)

def decrypt(message, key):
  return xor(message, key)

