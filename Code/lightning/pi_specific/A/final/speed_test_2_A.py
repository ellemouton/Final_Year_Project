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

sizes = [1,10,100,500]


for s in sizes:

    times = []

    for i in range(20):
        package = os.urandom(s)

        t0 = time.time()

        sock_B.send(package)
        sock_B.receive()

        t1 = time.time()

        total = t1 - t0

        times.append(total)

    fileName = 'results_2_'+str(s)+'.txt'
    with open(fileName, 'w') as f:
        f.truncate(0)

        for t in times:
            f.write('%.10f\n' % t)










