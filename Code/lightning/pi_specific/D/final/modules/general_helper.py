import json
from ecc import PrivateKey
from helper import hash256, little_endian_to_int, sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
from socket_helper import SocketError, SocketServer, SocketClient
from ecc import S256Point
import sys
from tx import Tx, TxIn, TxOut
from io import BytesIO
from script import Script, p2pkh_script

class BTC_node:
  def __init__(self, passphrase):
    self.secret = little_endian_to_int(hash256(passphrase))
    self.private_key = PrivateKey(self.secret)
    self.public_key = self.private_key.point
    self.address = self.public_key.address(testnet=True)

class Peer:
  def __init__(self, socket, btc_addr, public_key, sym_key):
    self.socket = socket
    self.btc_addr = btc_addr
    self.public_key = public_key
    self.sym_key = sym_key

  def send(self,data):
      self.socket.send(data)

  def receive(self,size=1024):
      return self.socket.receive(size)

  def __str__(self):
    return str(self.socket)+", peer btc address: "+str(self.btc_addr)

class Channel:
  def __init__(self, peer, local_amt, remote_amt, funding_tx):
    self.peer = peer
    self.local_amt = local_amt
    self.remote_amt = remote_amt
    self.funding_tx = funding_tx

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
    data['funding_tx'] = self.funding_tx.serialize().hex()
    return json.dumps(data)

  def reset(self, orientation):
    if orientation==0:
      self.local_amt = self.funding_tx.tx_ins[0].value()
      self.remote_amt = 0
    else:
      self.local_amt = 0
      self.remote_amt = self.funding_tx.tx_ins[0].value()

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
  peer_sym_key = node.secret*peer_pub_key_point

  return Peer(sock, peer_address, peer_pub_key_point, peer_sym_key)

def listen_for_new_peer_for_price(host, port):

  sock = SocketServer(host, port)
  sock.listen()
  return sock

def connect_peer(host, port, node):

  sock = SocketClient(host, port)
  sock.connect()

  peer_address = sock.receive()
  sock.send(str.encode(node.address))
  peer_pub_key = sock.receive()
  sock.send(node.public_key.sec())

  peer_pub_key_point = S256Point.parse(peer_pub_key)
  peer_sym_key = node.secret*peer_pub_key_point

  return Peer(sock, peer_address, peer_pub_key_point, peer_sym_key)

def connect_peer_for_price(host, port):

  sock = SocketClient(host, port)
  sock.connect()
  return sock

def add_channel(local_node, remote_peer, input_tx_id, input_tx_index):

  tx_in = TxIn(bytes.fromhex(input_tx_id), input_tx_index)
  local_amount = tx_in.value()
  remote_amount = 0

  # Construct the output: amount, scriptPubKey = 2-of-2 Bare Multisig  = Script([op_1, pubkey1, pubkey2, op_2, op_checkmultisig])
  scriptPubKey = Script([0x52, local_node.public_key.sec(), remote_peer.public_key.sec(), 0x52, 0xae])
  tx_out = TxOut(amount = local_amount, script_pubkey = scriptPubKey)

  # Construct the transaction object
  funding_tx = Tx(1, [tx_in], [tx_out], 0, True)

  # Sign the input
  funding_tx.sign_input(0, local_node.private_key)

  #send channel request
  new_channel = Channel(remote_peer, local_amount, remote_amount, funding_tx)
  remote_peer.send(str.encode(new_channel.toJSON()))

  return new_channel


def listen_for_channel_request(peer):

  request = json.loads(peer.receive())
  funding_tx = Tx.parse(BytesIO(bytes.fromhex(request['funding_tx'])))
  if(funding_tx.verify()):
    new_channel = Channel(peer, request['remote_amt'], request['local_amt'], funding_tx)
    return new_channel
  else:
    print("Invalid Channel Request")
    return None

def find_cheapest_route(routes):
  costs = []

  for i in range(len(routes)):
    cost = 0
    for n in routes[i]:
      cost += n[1]
    costs.append(cost)
  return costs.index(min(costs))

def route_cost(route, packet_size):
  cost = 0
  for n in route:
      cost += n[1]*packet_size
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

def get_channel_balance(channel):
  return channel.local_amt

def new_commitment_tx(node, current_channel, cost, secret_hash):

  remote_peer = current_channel.peer

  # Create input using the output from the funding tx
  tx_in = TxIn(bytes.fromhex(current_channel.funding_tx.id()), 0)

  # Create 3 outputs. 1 to nodeA and 1 to nodeB and 1 to an HTLC script
  script_1 = p2pkh_script(decode_base58(node.address))
  tx_out_1 = TxOut(amount = current_channel.local_amt - cost, script_pubkey = script_1)

  script_2 = p2pkh_script(decode_base58(remote_peer.btc_addr.decode()))
  tx_out_2 = TxOut(amount = current_channel.remote_amt, script_pubkey = script_2)

  #script_3 HTLC
  script_3 = Script([99,168, secret_hash, 136, 118, 169, hash160(remote_peer.public_key.sec()), 103, encode_varint(1000), 177, 117, 118, 169, hash160(node.public_key.sec()), 104, 136, 172])
  tx_out_3 = TxOut(amount = cost, script_pubkey = script_3)

  # Construct the commitment tx object
  commitment_tx = Tx(1, [tx_in], [tx_out_1, tx_out_2, tx_out_3], 0, True)

  #sign it
  z = commitment_tx.sig_hash(0)
  signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
  script_sig = Script([0x0, signature])
  commitment_tx.tx_ins[0].script_sig = script_sig

  return commitment_tx

def check_htlc(node, commitment_tx, secret):

    tx_in = TxIn(bytes.fromhex(commitment_tx.id()), 2)
    tx_out = TxOut(amount = commitment_tx.tx_outs[2].amount, script_pubkey = commitment_tx.tx_outs[0].script_pubkey)
    spendingTx = Tx(1, [tx_in], [tx_out], 0, True)

    z = spendingTx.sig_hash(0)
    signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
    combined = Script([signature, node.public_key.sec(), str.encode(secret), b'1']) + commitment_tx.tx_outs[2].script_pubkey
    
    return combined.evaluate(z, None)

def check_htlc_and_get_secret_hash(node, commitment_tx, channel):
    tx_in = commitment_tx.tx_ins[0]
    tx_out_1 = commitment_tx.tx_outs[1]
    tx_out_2 = commitment_tx.tx_outs[2]
    
    if(tx_in.prev_tx.hex() ==  channel.funding_tx.id()): #checks that it is spending from the correct 2-of-2 multisig tx (the funding tx)
        if(tx_out_1.script_pubkey.cmds[2] == decode_base58(node.address) and tx_out_1.amount == channel.local_amt):
            if(tx_out_2.script_pubkey.cmds[6] == hash160(node.public_key.sec())):
                return tx_out_2.script_pubkey.cmds[2]
    return None  


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

