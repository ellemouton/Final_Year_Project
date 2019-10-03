'''
Imports and determine if running on Mac or RPi
'''
import platform
import sys

global system

if(platform.platform()[0:3]=="Lin"):
  system = 0 #RPi
  sys.path.insert(0, '/home/pi/Documents/final/modules')
else:
  system = 1 #Mac
  sys.path.insert(0, '/Users/ellemouton/Documents/2019/Sem2/EEE4022S/Code/lightning/modules')

from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import secrets
import json
import threading
import tkinter as tk
from random import randint
import shamir


global go
go = True
'''
      #Set up node, peers and channels
'''
global host
global host_C
global host_B
global host_D

peers =[]
channels =[]
global packet_size_main
global num_packets_main
global total_bytes_sent_main

prices = {"n1weDdde5xXLfPeutESLaG8swr5jLCqz72": 0, "mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn": 0, "mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW": 0}

''' GUI '''
def reset_variables():
  global total_bytes_sent_main
  global num_packets_main
  global packet_size_main

  total_bytes_sent_main = 0
  packet_size_main = 0
  num_packets_main = 0

  num_packets.set(num_packets_main)
  packet_size.set(packet_size_main)
  total_bytes_sent.set(total_bytes_sent_main)


def reset_channels():
  global channels

  channels[0].reset(0)
  channels[1].reset(0)

  wallet_balance = get_total_channel_balance(channels)
  local_balance_AB = get_channel_balance(channels[0])
  local_balance_AD = get_channel_balance(channels[1])

  totalBalance.set(wallet_balance)
  channel_B_local.set(local_balance_AB)
  channel_D_local.set(local_balance_AD)

def set_up():
  reset_variables()
  reset_channels()


def swap_packet_size_multiple():
  global current_packet_multiple

  if(current_packet_multiple==7):
    current_packet_multiple = 8
  else:
    current_packet_multiple = 7

def increase_bytes():
    global packet_size_main
    global go

    go = True

    val = packet_size.get()+1

    packet_size.set(val)
    packet_size_main = val


def decrease_bytes():
    global packet_size_main
    global go

    go = True

    val = packet_size.get()-1

    if(val <= 0):
        val = 0

    packet_size_main = val
    packet_size.set(val)


def increase_packet_num():
    global num_packets_main
    global go

    go = True

    val = num_packets.get()+1

    num_packets.set(val)
    num_packets_main = val


def decrease_packet_num():
    global num_packets_main
    global go

    go = True

    val = num_packets.get()-1

    if(val <= 0):
        val = 0

    num_packets_main= val
    num_packets.set(val)

# Create the main window
root = tk.Tk()
root.title("Node A: Client")
bg_colour = "cyan"

# Create the main container
frame = tk.Frame(root, bg=bg_colour)

# Lay out the main container, specify that we want it to grow with window size
frame.pack(fill=tk.BOTH, expand=True)

# Allow middle cell of grid to grow when window is resized
frame.columnconfigure(2, weight=1)


# Variables for holding temperature data
num_packets = tk.IntVar()
packet_size = tk.IntVar()
totalBalance = tk.IntVar()
channel_B_local = tk.IntVar()
channel_D_local = tk.IntVar()
total_bytes_sent = tk.IntVar()

totalBalance.set(0)
channel_B_local.set(0)
channel_D_local.set(0)
packet_size.set(0)
total_bytes_sent.set(0)
num_packets.set(0)

# Create widgets
button_up_packets = tk.Button(frame, text="Up", command=increase_packet_num)
button_down_packets = tk.Button(frame, text="Down", command=decrease_packet_num)
label_num_packets = tk.Label(frame, textvariable=num_packets, bg=bg_colour)
label_packet_size = tk.Label(frame, textvariable=packet_size, bg=bg_colour)
label_x = tk.Label(frame, text="X", bg=bg_colour)
label_kB = tk.Label(frame, text="kB", bg=bg_colour)
button_up_bytes = tk.Button(frame, text="Up", command=increase_bytes)
button_down_bytes = tk.Button(frame, text="Down", command=decrease_bytes)
label_wallet_balance_label = tk.Label(frame, text="Total Balance:", font=('Helvetica', 13, 'bold', 'italic'), bg=bg_colour)
label_wallet_balance = tk.Label(frame, textvariable = totalBalance, bg=bg_colour)
label_chan_B_balance = tk.Label(frame, text="Channel A-B:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_B_label = tk.Label(frame, textvariable = channel_B_local, bg=bg_colour)
label_chan_D_balance = tk.Label(frame, text="Channel A-D:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_D_label = tk.Label(frame, textvariable = channel_D_local, bg=bg_colour)
label_status = tk.Label(frame, text="Node A: Client", font=('Symbol', 20, 'bold'), bg=bg_colour)
label_bytes_sent_label = tk.Label(frame, text="Total kB sent:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_bytes_sent = tk.Label(frame, textvariable = total_bytes_sent, bg=bg_colour)
button_reset = tk.Button(frame, text="reset", command=set_up)

# Lay out widgets
label_num_packets.grid(row=2, column=2, padx=5, columnspan=1, pady=5)
label_packet_size.grid(row=2, column=3, padx=5, columnspan=1, pady=5)
label_x.grid(row=2, column=3, padx=5, pady=5, sticky=tk.W)
label_kB.grid(row=2, column=4, padx=5, pady=5, sticky=tk.W)
button_up_packets.grid(row=1, column=2, columnspan=1, padx=5, pady=5)
button_down_packets.grid(row=3, column=2, columnspan=1, padx=5, pady=5)
button_up_bytes.grid(row=1, column=3, columnspan=1, padx=5, pady=5)
button_down_bytes.grid(row=3, column=3, columnspan=1, padx=5, pady=5)
label_wallet_balance_label.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
label_wallet_balance.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
label_chan_B_balance.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
label_chan_B_label.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
label_chan_D_balance.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
label_chan_D_label.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
label_status.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky=tk.E)
label_bytes_sent_label.grid(row=5, column=3, padx=5, pady=5)
label_bytes_sent.grid(row=5, column=4, padx=5, pady=5)
button_reset.grid(row=0, column=4, padx=5, pady=5)

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

reset_variables()

#Get A's wallet transaction
input_tx_id_1 = 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
input_tx_index_1 = 1

input_tx_id_2 = '15fccae87a15395af0232ba7e1a5659a6d3ca67c90ebdf900025753fb6a57f3e'
input_tx_index_2 = 0

#Automatically connect to peers C and B and D
if(system==0):
  host_C = '169.254.10.3'
  host_B = '169.254.10.1'
  host_D = '169.254.10.10'
else:
  host_C = '127.0.0.1'
  host_B = '127.0.0.1'
  host_D = '127.0.0.1'

peers.append(connect_peer(host_C, 3002, node))
peers.append(connect_peer(host_B, 2000, node))
peers.append(connect_peer(host_D, 4000, node))

for p in peers:
  print(p)

#Automatically connect channel with B and D
channels.append(add_channel(node, peers[1], input_tx_id_1, input_tx_index_1))
channels.append(add_channel(node, peers[2], input_tx_id_2, input_tx_index_2))

for c in channels:
  print(c)


'''
 Start Sending Packets
'''

print("----Send Mode----")

def send_packets():
  global packet_size_main
  global num_packets_main
  global total_bytes_sent_main
  global go

  # destination (C's address (or rather, the Gateways BTC address))
  destination = 'n1weDdde5xXLfPeutESLaG8swr5jLCqz72'
  sym_key_dest = get_peer(peers, destination).sym_key

  wallet_balance = get_total_channel_balance(channels)
  local_balance_AB = get_channel_balance(channels[0])
  local_balance_AD = get_channel_balance(channels[1])
  totalBalance.set(wallet_balance)
  channel_B_local.set(local_balance_AB)
  channel_D_local.set(local_balance_AD)


  while True:

    packet_size_freeze = packet_size_main*1000 #convert from kB to B
    num_packets_freeze = num_packets_main
    num_bytes = packet_size_freeze*num_packets_freeze
    num_kilobytes = int(num_bytes/1000)

    if(packet_size_freeze>0 and num_packets_freeze>0):# and go==True):

      # find routes
      routes = [[['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn', prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]],
                [['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW', prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW']], ['n1weDdde5xXLfPeutESLaG8swr5jLCqz72', prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72']]]]


      #body: secret and actual message -> encrypt for destination

      packet_payloads = []

      if(num_packets_freeze==1):
        X = randint(1000000000000000000000000000000000000000, 2000000000000000000000000000000000000000)
        shares = [X]
      else:
        X, shares = shamir.make_random_shares(num_packets_freeze, num_packets_freeze)

      H = sha256(str.encode(str(X)))

      for i in range(num_packets_freeze):
        message = secrets.token_urlsafe(packet_size_freeze)
        secret_share = str(shares[i])
        body = {"secret_share":secret_share, "message":message}
        encrypted_body = encrypt(str.encode(json.dumps(body)), sym_key_dest.sec())
        packet_payloads.append(encrypted_body)

      success = False

      while success == False:

        # Find cost of each route and choose cheapest
        cheap_route_index = find_cheapest_route(routes)
        cheapest_route = routes[cheap_route_index]

        # get next hop from route and hence get relevent channel
        next_hop = get_peer(peers, routes[cheap_route_index][0][0])
        next_hop_channel = get_channel(next_hop, channels)

        cost = route_cost(cheapest_route, num_kilobytes)
        commitment_tx = new_commitment_tx(node, next_hop_channel, cost, H)
        header = {"source":node.address, "route": cheapest_route, "num_packets":num_packets_freeze, "packet_size": packet_size_freeze, "commitment_tx": str(commitment_tx.serialize().hex())}

        # send header
        next_hop.send(str.encode(json.dumps(header)))

        if(next_hop.receive()==b'header ACK'):

          for i in range(num_packets_freeze):
            print(sys.getsizeof(packet_payloads[i]))
            next_hop.send(packet_payloads[i])
            next_hop.receive()

        reply = json.loads(next_hop.receive().decode())
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
        revealed_secret = reply['secret']

        if(revealed_secret == X):
          print("Successful delivery of message proven. Thus update channel state")
          success = True

          next_hop_channel.pay(commitment_tx.tx_outs[2].amount)

          print(get_channel(next_hop, channels))


          total_bytes_sent_main += num_kilobytes
          total_bytes_sent.set(total_bytes_sent_main)

          wallet_balance = get_total_channel_balance(channels)
          local_balance_AB = get_channel_balance(channels[0])
          local_balance_AD = get_channel_balance(channels[1])

          totalBalance.set(wallet_balance)
          channel_B_local.set(local_balance_AB)
          channel_D_local.set(local_balance_AD)

          print("Total Balance: "+str(wallet_balance))
          go = False

        else:
          print("Malicious node detected, choose next cheapest route")
          routes.pop(cheap_route_index)
          go = False

'''
Price update
'''

def get_B_price():
  sock = connect_peer_for_price(host_B, 5000)

  try:
    while True:

      try:
          price = int.from_bytes(sock.receive(), 'little')
          prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'] =  price
      except:
          print("Wrong type received")
  finally:
    sock.close()

def get_D_price():
  sock = connect_peer_for_price(host_D, 6000)

  try:
    while True:

      try:
          price = int.from_bytes(sock.receive(), 'little')
          prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'] =  price
      except:
          print("Wrong type received")
  finally:
    sock.close()

def get_C_price():
  sock = connect_peer_for_price(host_C, 7000)

  try:
    while True:

      try:
          price = int.from_bytes(sock.receive(), 'little')
          prices['n1weDdde5xXLfPeutESLaG8swr5jLCqz72'] =  price
      except:
          print("Wrong type received")
  finally:
    sock.close()



input("say when")
price_B = threading.Thread(target = get_B_price)
price_B.start()

price_D = threading.Thread(target = get_D_price)
price_D.start()

price_C = threading.Thread(target = get_C_price)
price_C.start()

send = threading.Thread(target = send_packets)
send.start()

# Run forever!
root.mainloop()










