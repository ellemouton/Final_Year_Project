from socket_helper import SocketError, SocketServer, SocketClient
import threading
import json
import sys


def get_B_price():
  sock = connect_peer('127.0.0.1', 5000)
  #sock = connect_peer('169.254.10.1', 5000)

  try:
    while True:

      try:
          price = int.from_bytes(sock.receive(), 'little')
          prices = json.load(open("peer_prices.txt"))
          prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'] =  price
          json.dump(prices, open("peer_prices.txt",'w'))
      except:
          print("Wrong type received")

  finally:
    sock.close()

def get_D_price():
  sock = connect_peer('127.0.0.1', 6000)
  #sock = connect_peer('169.254.10.10', 6000)

  try:
    while True:

      try:
          price = int.from_bytes(sock.receive(), 'little')
          prices = json.load(open("peer_prices.txt"))
          prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'] =  price
          json.dump(prices, open("peer_prices.txt",'w'))
      except:
          print("Wrong type received")

  finally:
    sock.close()

def connect_peer(host, port):

  sock = SocketClient(host, port)
  sock.connect()
  return sock


sockB = threading.Thread(target = get_B_price)
sockB.start()

sockD = threading.Thread(target = get_D_price)
sockD.start()
