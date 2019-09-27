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
from general_helper import *
from time import sleep

global host
global host_C


if(system==0):
  host = '169.254.10.1'
  host_C = '169.254.10.3'
else:
  host = '127.0.0.1'
  host_C = '127.0.0.1'

port_B = 2000
port_C = 3000

sock_C = SocketClient(host_C, port_C)
sock_C.connect()

print("Listening on: "+host+":"+str(port_B)+".....")
sock_A = SocketServer(host, port_B)
sock_A.listen()

while True:
  package = sock_A.receive()
  sock_C.send(package)

  ack = sock_C.receive()
  sock_A.send(ack)


