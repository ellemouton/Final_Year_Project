from socket_helper import SocketError, SocketServer

def listen_for_new_peer(host, port):

  sock = SocketServer(host, port)
  sock.listen()

  return sock

def connect_peer(host, port):

  sock = SocketClient(host, port)
  sock.connect()

  return sock

host = '127.0.0.1'
port = 2000

sock = listen_for_new_peer(host, port)


sock.send(b'1')

print(sock.receive())