from socket_helper import SocketError, SocketServer

def listen_for_new_peer_for_price(host, port):

  sock = SocketServer(host, port)
  sock.listen()
  return sock


#host = '127.0.0.1'
host = '169.254.10.1'
port = 5000

sock = listen_for_new_peer_for_price(host, port)

try:
	while True:
		new_price = int(input("Set new price (sats/byte): "))
		sock.send(new_price.to_bytes(4, 'little'))
finally:
	sock.close()
