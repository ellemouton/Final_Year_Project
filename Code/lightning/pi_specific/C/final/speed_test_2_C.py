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

global host

peers = []
channels = []

if(system==0):
  host = '169.254.10.3'
else:
  host = '127.0.0.1'

port_C = 3000

print("Listening on: "+host+":"+str(port_C)+".....")
sock_B = SocketServer(host, port_C)
sock_B.listen()


while True:

	sock_B.receive()

	sock_B.send(b'1')

