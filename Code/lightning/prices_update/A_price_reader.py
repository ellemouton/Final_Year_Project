from socket_helper import SocketError, SocketServer, SocketClient
import threading
import json
import sys


def get_B_price():
	sock = connect_peer('127.0.0.1', 5000)
	
	while True:
		new_price = int.from_bytes(sock.receive(), 'little')
		prices = json.load(open("peer_prices.txt"))
		prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'] = new_price
		json.dump(prices, open("peer_prices.txt",'w'))

def get_D_price():
	sock = connect_peer('127.0.0.1', 6000)
	
	while True:
		new_price = int.from_bytes(sock.receive(), 'little')
		prices = json.load(open("peer_prices.txt"))
		prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'] = new_price
		json.dump(prices, open("peer_prices.txt",'w'))


def connect_peer(host, port):

  sock = SocketClient(host, port)
  sock.connect()
  return sock


sockB = threading.Thread(target = get_B_price)
sockB.start()

sockD = threading.Thread(target = get_D_price)
sockD.start()