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
port_C += 1

print("Listening on: "+host+":"+str(port_C)+".....")
sock_A = SocketServer(host, port_C)
sock_A.listen()


sizes = [1,10,100,500]

for s in sizes:

    times = []

    for i in range(20):

        sock_A.receive()
        t0 = time.time()
        sock_B.receive()
        t1 = time.time()

        total = t1-t0
        times.append(total)

    fileName = 'results_1_'+str(s)+'.txt'
    with open(fileName, 'w') as f:
        f.truncate(0)

        for t in times:
            f.write('%.10f\n' % t)



