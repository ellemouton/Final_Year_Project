from socket_helper import SocketError, SocketServer, SocketClient

def listen_for_new_peer(host, port):

  sock = SocketServer(host, port)
  sock.listen()

  return sock

def connect_peer(host, port):

  sock = SocketClient(host, port)
  sock.connect()

  return sock

host = '127.0.0.1'
port = 3000

sockC = connect_peer('127.0.0.1', 2000)
sockA = listen_for_new_peer(host, port)


	
print(sockC.receive())
sockA.send(b'2')

print(sockA.receive())
sockC.send(b'4')