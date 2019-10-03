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
      #Set up node, peers and channels
'''

peers =[]
channels =[]
global packet_size_main
global current_packet_multiple
global total_bytes_sent_main
global total_sat_paid_main

prices = {"n1weDdde5xXLfPeutESLaG8swr5jLCqz72": 0, "mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn": 0, "mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW": 0}

def set_up():
  print("reset")

def swap_packet_size_multiple():
  global current_packet_multiple

  if(current_packet_multiple==7):
    current_packet_multiple = 8
  else:
    current_packet_multiple = 7

def increase_bytes():
    global packet_size
    global go

    go = True

    packet_size.set(packet_size.get()+100)


def decrease_bytes():
    global packet_size
    global go

    go = True

    val = packet_size.get()-100

    if(val <= 0):
        packet_size.set(0)
    else:
        packet_size.set(val)

def increase_packet_num():
    global num_packets
    global go

    go = True
    num_packets.set(num_packets.get()+10)


def decrease_packet_num():
    global num_packets
    global go

    go = True
    
    val = num_packets.get()-10

    if(val <= 0):
        num_packets.set(0)
    else:
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
label_bytes_sent_label = tk.Label(frame, text="Total bytes sent:", font=('Helvetica', 13, 'bold'), bg=bg_colour)
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


# Run forever!
root.mainloop()










