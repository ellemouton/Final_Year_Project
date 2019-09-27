''' 
Imports and determine if running on Mac or RPi
'''
import platform
import sys
import time

global system

if(platform.platform()[0:3]=="Lin"):
  system = 0 #RPi
  sys.path.insert(0, '/home/pi/Documents/final/modules')
else:
  system = 1 #Mac
  sys.path.insert(0, '/Users/ellemouton/Documents/2019/Sem2/EEE4022S/Code/lightning/modules')

from socket_helper import SocketError, SocketClient, SocketServer
from general_helper import *
from time import sleep
import os

global host_B
global host_C

if(system==0):
  host_B = '169.254.10.1'
  host_C = '169.254.10.3'
else:
  host_B = '127.0.0.1'
  host_C = '127.0.0.1'

port_B = 2000
port_C = 3001

sock_B = SocketClient(host_B, port_B)
sock_B.connect()

sock_C = SocketClient(host_C, port_C)
sock_C.connect()

while True:
	num_bytes = int(input("Num bytes? "))
	package = os.urandom(num_bytes)
	sock_C.send(b'1')
	sock_B.send(package)









