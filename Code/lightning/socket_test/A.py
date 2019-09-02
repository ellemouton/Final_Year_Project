from socket_helper import SocketError, SocketServer, SocketClient

def listen_for_new_peer(host, port):

  sock = SocketServer(host, port)
  sock.listen()

  return sock

def connect_peer(host, port):

  sock = SocketClient(host, port)
  sock.connect()

  return sock


sock = connect_peer('127.0.0.1', 3000)


print(sock.receive())
sock.send(b'3')