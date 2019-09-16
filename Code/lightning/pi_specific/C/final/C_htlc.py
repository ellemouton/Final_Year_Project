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


'''
      Set up node, peers and channels
'''
global host

peers = []
channels = []

if(system==0):
  host = '169.254.10.3'
else:
  host = '127.0.0.1'

port = 3000


'''
GUI
'''

global price_sock
global price 

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
root.title("Node C: Gateway")
bg_colour = "hot pink"

# Create the main container
frame = tk.Frame(root, bg=bg_colour)

# Lay out the main container, specify that we want it to grow with window size
frame.pack(fill=tk.BOTH, expand=True)

# Allow middle cell of grid to grow when window is resized
frame.columnconfigure(2, weight=1)
frame.rowconfigure(3, weight=1)
frame.rowconfigure(5, weight=1)


# Variables for holding temperature data
price = tk.IntVar()
totalBalance = tk.IntVar()
channel_B_local = tk.IntVar()
channel_D_local = tk.IntVar()

price.set(0)
totalBalance.set(0)
channel_B_local.set(0)
channel_D_local.set(0)

# Create widgets
button_up = tk.Button(frame, text="Up", command=increase)
label_size = tk.Label(frame, textvariable = price, bg=bg_colour)
label_unit_packet = tk.Label(frame, text="sat/byte", bg=bg_colour)
button_down = tk.Button(frame, text="Down", command=decrease, bg=bg_colour)
label_wallet_balance_label = tk.Label(frame, text="Total Wallet Balance:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_wallet_balance = tk.Label(frame, textvariable = totalBalance, bg=bg_colour)
label_chan_B_balance = tk.Label(frame, text="Channel C-B Local Balance:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_B_label = tk.Label(frame, textvariable = channel_B_local, bg=bg_colour)
label_chan_D_balance = tk.Label(frame, text="Channel C-D Local Balance:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
label_chan_D_label = tk.Label(frame, textvariable = channel_D_local, bg=bg_colour)
label_status = tk.Label(frame, text="Node C: Receiving Data", font=('Helvetica', 17, 'bold'), bg=bg_colour)


# Lay out widgets
label_size.grid(row=2, column=3, padx=5, pady=5)
label_unit_packet.grid(row=2, column=4, padx=5, pady=5)
button_up.grid(row=1, column=3, columnspan=2, padx=5, pady=5)
button_down.grid(row=3, column=3, columnspan=2, padx=5, pady=5)
label_wallet_balance_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
label_wallet_balance.grid(row=1, column=1, padx=5, pady=5)
label_chan_B_balance.grid(row=2, column=0, padx=5, pady=5)
label_chan_B_label.grid(row=2, column=1, padx=5, pady=5)
label_chan_D_balance.grid(row=3, column=0, padx=5, pady=5)
label_chan_D_label.grid(row=3, column=1, padx=5, pady=5)
label_status.grid(row=0, column=1, columnspan=3, padx=5, pady=5)


def sock_checker(node_address):
    prev_hop = get_peer(peers, node_address)
    current_channel = get_channel(prev_hop, channels)
    sym_key_prev_hop = prev_hop.sym_key

    while True:

        # receive header
        received_header = prev_hop.receive()
        decrypted_header = json.loads(decrypt(received_header, sym_key_prev_hop.sec()).decode())
        source = get_peer(peers, decrypted_header['source'])
        commitment_tx = Tx.parse(BytesIO(bytes.fromhex(decrypted_header['commitment_tx'])))
        secret_hash = check_htlc_and_get_secret_hash(node, commitment_tx, current_channel)
        prev_hop.send(b'header ACK')

        #receive body
        sym_key_source = source.sym_key
        encrypted_body = prev_hop.receive()
        decrypted_message = json.loads(decrypt(encrypted_body, sym_key_source.sec()).decode())
        revealed_secret = decrypted_message['secret']
        cost_paid = route_cost(decrypted_header['route'], len(encrypted_body))

        #check that you can suceesfully unlock the htlc output
        if(not (secret_hash == None) and (sha256(str.encode(revealed_secret)) == secret_hash)):
            print("I can sign the htlc output with the secret")

            #sign the commitment tx
            z = commitment_tx.sig_hash(0)
            signature = node.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
            script_sig = commitment_tx.tx_ins[0].script_sig + Script([signature])
            commitment_tx.tx_ins[0].script_sig = script_sig

            reply = {"commitment_tx": str(commitment_tx.serialize().hex()), "secret": revealed_secret}

            prev_hop.send(str.encode(json.dumps(reply)))

            current_channel.paid(commitment_tx.tx_outs[2].amount)
            print(current_channel)

            wallet_balance = get_total_channel_balance(channels)
            local_balance_CB = get_channel_balance(channels[0])
            local_balance_CD = get_channel_balance(channels[1])

            totalBalance.set(wallet_balance)
            channel_B_local.set(local_balance_CB)
            channel_D_local.set(local_balance_CD)

            print("Total Balance: "+str(get_total_channel_balance(channels)))

        else:
            print("Cannot unlock HTLC")

'''
create BTC address. secret -> private key -> public key
'''
node = BTC_node(b'nodeC')
print("Node Bitcoin Address: "+str(node.address))


'''
Automatically listen for peers A, B and D
'''
# peer B
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer D
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer A
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

'''
Automatically listen for channels from B and D
'''
channels.append(listen_for_channel_request(peers[0]))
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)

print("----Receive Mode----")


sockB = threading.Thread(target = sock_checker, kwargs = dict(node_address = 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'))
sockB.start()

sockD = threading.Thread(target = sock_checker, kwargs = dict(node_address = 'mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'))
sockD.start()

price_sock = listen_for_new_peer_for_price(host, 7000)

# Run forever!
root.mainloop()
