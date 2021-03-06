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

from socket_helper import SocketError, SocketClient, SocketServer
import tkinter as tk
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL, int_to_little_endian, encode_varint, hash160
import secrets
import json
import threading
from random import randint

'''
      Set up node, peers and channels
'''
global host
global host_C
global channels

peers = []
channels = []

if(system==0):
  host = '169.254.10.1'
  host_C = '169.254.10.3'
else:
  host = '127.0.0.1'
  host_C = '127.0.0.1'

port = 2000

'''
GUI
'''

global price_sock
global price 
global evil
global frame

def reset_variables():
  global total_bytes_routed_main

  total_bytes_routed_main = 0

def reset_channels():
  global channels
  global total_bytes_routed_main

  channels[0].reset(0)
  channels[1].reset(1)

  wallet_balance = get_total_channel_balance(channels)
  local_balance_BC = get_channel_balance(channels[0])
  local_balance_BA = get_channel_balance(channels[1])

  totalBalance.set(wallet_balance)
  channel_A_local.set(local_balance_BA)
  channel_C_local.set(local_balance_BC)
  total_bytes_routed.set(total_bytes_routed_main)

def set_up():
  reset_variables()
  reset_channels()


def malicious():
    global evil
    global frame

    evil = not evil

    if evil:
      frame['bg']="red"
    else:
      frame['bg']="yellow"

def increase():
    global price
    global price_sock
    
    new_price = price.get()+1
    price.set(new_price)
    price_sock.send(new_price.to_bytes(4, 'little'))

def decrease():
    global price
    global price_sock

    val = price.get()

    if(val ==0):
        pass
    else:
        new_price = val-1
        price.set(new_price)
        price_sock.send(new_price.to_bytes(4, 'little'))

# Create the main window
root = tk.Tk()
root.title("Node B: Router")
bg_colour = "yellow"

# Create the main container
frame = tk.Frame(root, bg=bg_colour)

# Lay out the main container, specify that we want it to grow with window size
frame.pack(fill=tk.BOTH, expand=True)

# Allow middle cell of grid to grow when window is resized
frame.columnconfigure(2, weight=1)

# Variables for holding temperature data
price = tk.IntVar()
totalBalance = tk.IntVar()
channel_A_local = tk.IntVar()
channel_C_local = tk.IntVar()
total_bytes_routed = tk.IntVar()

price.set(0)
totalBalance.set(0)
channel_A_local.set(0)
channel_C_local.set(0)
total_bytes_routed.set(0)

# Create widgets
button_up = tk.Button(frame, text="Up", command=increase)
label_size = tk.Label(frame, textvariable = price, bg=bg_colour)
label_unit_packet = tk.Label(frame, text="sat/byte", bg=bg_colour)
button_down = tk.Button(frame, text="Down", command=decrease)
button_evil= tk.Button(frame, text="Malicious", command=malicious)
label_wallet_balance_label = tk.Label(frame, text="Total Wallet Balance:", font=('Helvetica', 13, 'bold', 'italic'), bg=bg_colour)
label_wallet_balance = tk.Label(frame, textvariable = totalBalance, bg=bg_colour)
label_chan_B_balance = tk.Label(frame, text="Channel A-B Local:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_B_label = tk.Label(frame, textvariable = channel_A_local, bg=bg_colour)
label_chan_D_balance = tk.Label(frame, text="Channel B-C Local:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_D_label = tk.Label(frame, textvariable = channel_C_local, bg=bg_colour)
label_status = tk.Label(frame, text="Node B: Relay", font=('Symbol', 20, 'bold'), bg=bg_colour)
label_bytes_routed_label = tk.Label(frame, text="Total bytes routed:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_bytes_routed = tk.Label(frame, textvariable = total_bytes_routed, bg=bg_colour)
button_reset = tk.Button(frame, text="reset", command=set_up)


# Lay out widgets
label_size.grid(row=2, column=2, columnspan=2, padx=5, pady=5)
label_unit_packet.grid(row=2, column=3, padx=5, pady=5, sticky=tk.E)
button_up.grid(row=1, column=2, columnspan=2, padx=5, pady=5)
button_down.grid(row=3, column=2, columnspan=2, padx=5, pady=5)
button_evil.grid(row=0, column=3, padx=5, pady=5)
label_wallet_balance_label.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
label_wallet_balance.grid(row=5, column=1, padx=5, pady=5)
label_chan_B_balance.grid(row=2, column=0, padx=5, pady=5)
label_chan_B_label.grid(row=2, column=1, padx=5, pady=5)
label_chan_D_balance.grid(row=3, column=0, padx=5, pady=5)
label_chan_D_label.grid(row=3, column=1, padx=5, pady=5)
label_status.grid(row=0, column=0, columnspan=3, padx=5, pady=5)
label_bytes_routed_label.grid(row=5, column=3, padx=5, pady=5)
label_bytes_routed.grid(row=5, column=4, padx=5, pady=5)
button_reset.grid(row=0, column=4, padx=5, pady=5)



# create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeB')
print("Node Bitcoin Address: "+str(node.address))

evil = False

reset_variables()

# Get B's wallet transaction
input_tx_id = '77535a39b5397a851539d4381ce3000bb5932ef6d7857e9c6e3e1aed6dd43216'
input_tx_index = 0

# Automatically connect to peers C
peers.append(connect_peer(host_C, 3000, node))

# Automatically listen for peer A
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

# Automatically connect channel with C
channels.append(add_channel(node, peers[0], input_tx_id, input_tx_index))

# Automatically listen for channels from A
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)


def routing():
  global total_bytes_routed_main
  global evil

  print("----Route Mode----")

  #Symm key for A
  prev_hop = get_peer(peers, 'mst8broiaX4PFMFNbjfrBnMSnrVF42Jgd7')
  prev_hop_channel = get_channel(prev_hop, channels)
  sym_key_prev_hop = prev_hop.sym_key

  wallet_balance = get_total_channel_balance(channels)
  local_balance_BC = get_channel_balance(channels[0])
  local_balance_BA = get_channel_balance(channels[1])

  totalBalance.set(wallet_balance)
  channel_A_local.set(local_balance_BA)
  channel_C_local.set(local_balance_BC)

  while True:
      
      received_header = json.loads((prev_hop.receive()).decode())

      if evil:
       
        commitment_tx_prev_hop = Tx.parse(BytesIO(bytes.fromhex(received_header['commitment_tx'])))
        num_packets = received_header['num_packets']

        prev_hop.send(b'header ACK')

        for i in range(num_packets):
          prev_hop.receive()
          prev_hop.send(b'packet ACK')


        #sign the commitment tx
        commitment_tx_prev_hop.tx_ins[0].script_sig = get_script_sig(commitment_tx_prev_hop, node.private_key)

        #construct fake secret
        fake_secret = randint(1000000000000000000000000000000000000000, 2000000000000000000000000000000000000000)

        reply = {"commitment_tx": str(commitment_tx_prev_hop.serialize().hex()), "secret": fake_secret}

        prev_hop.send(str.encode(json.dumps(reply)))


      else:

        commitment_tx_prev_hop = Tx.parse(BytesIO(bytes.fromhex(received_header['commitment_tx'])))
        H = check_htlc_and_get_secret_hash(node, commitment_tx_prev_hop, prev_hop_channel)
        num_packets = received_header['num_packets']
        packet_size = received_header['packet_size']
        num_bytes = num_packets*packet_size
        #num_kilobytes = int(num_packets*packet_size/1000)

        #receive packets
        

        prev_hop.send(b'header ACK')

        packet_payloads = []
        for i in range(num_packets):
          packet_payloads.append(prev_hop.receive())
          prev_hop.send(b'packet ACK')
          
        cost_paid = int(route_cost(received_header['route'], num_bytes))
        
        #adapt header for next hop
        header = received_header
        header['route'] = received_header['route'][1:]
        cost_to_pay = int(route_cost(header['route'], num_bytes))

        next_hop = get_peer(peers, header['route'][0][0])
        next_hop_channel = get_channel(next_hop, channels)

        commitment_tx_next_hop = new_commitment_tx(node, next_hop_channel, cost_to_pay, H)
        header['commitment_tx'] = str(commitment_tx_next_hop.serialize().hex())

        #send header
        next_hop.send(str.encode(json.dumps(header)))

        if(next_hop.receive()==b'header ACK'):

          for i in range(num_packets):
            next_hop.send(packet_payloads[i])
            next_hop.receive()

        reply = json.loads(next_hop.receive().decode())
        commitment_tx_next_hop = Tx.parse(BytesIO(bytes.fromhex(reply['commitment_tx'])))
        revealed_secret = reply['secret']

        if(not (H == None) and (sha256(str.encode(str(revealed_secret))) == H)):
            print("I can sign the htlc output with the secret")

            next_hop_channel.pay(cost_to_pay)

            #sign the commitment tx
            commitment_tx_prev_hop.tx_ins[0].script_sig = get_script_sig(commitment_tx_prev_hop, node.private_key)

            reply = {"commitment_tx": str(commitment_tx_prev_hop.serialize().hex()), "secret": revealed_secret}

            prev_hop.send(str.encode(json.dumps(reply)))

            prev_hop_channel.paid(cost_paid)
            
            for c in channels:
              print(c)


            total_bytes_routed_main += num_bytes
            total_bytes_routed.set(total_bytes_routed_main)

            wallet_balance = get_total_channel_balance(channels)
            local_balance_BC = get_channel_balance(channels[0])
            local_balance_BA = get_channel_balance(channels[1])

            totalBalance.set(wallet_balance)
            channel_A_local.set(local_balance_BA)
            channel_C_local.set(local_balance_BC)

            print("Total Balance: "+str(wallet_balance))

        else:
            print("Cannot unlock HTLC")



price_sock = listen_for_new_peer_for_price(host, 5000)

route = threading.Thread(target = routing)
route.start()

# Run forever!
root.mainloop()
