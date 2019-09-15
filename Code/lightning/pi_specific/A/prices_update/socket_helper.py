import socket

class SocketError(Exception):
  pass

class SocketServer:
  def __init__(self,host,port):
    self.host = host
    self.port = port
    
    try:
      self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    except socket.error as msg:
      print("Socket Error : %s" % msg)
    
    try:
      self.sock.bind((self.host,self.port))
    except socket.error as msg:
      print("Socket Error : %s" % msg)

  def listen(self):

    print('Listening to port '+str(self.port))
    self.sock.listen(1)
    self.conn,self.addr = self.sock.accept()
    self.addr=self.addr[0]

    if self.addr:
      print('Got connection from',self.host)
      
  def send(self,data):
    #print('Sending data of size ',len(data))
    self.conn.send(data)
    #print('Data sent!!')

  def receive(self,size=1024):
    #print('Receiving data...')
    return self.conn.recv(size)

  def close(self):
    self.sock.close()

  def __str__(self):
    return 'Socket bound to Host='+str(self.host)+',Port='+str(self.port)


class SocketClient:

  def __init__(self,host,port):
    self.host=host
    self.port=port

    try:
      self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    except socket.error as msg:
      print("Socket Error : %s" % msg)

  def connect(self):

    try:
      self.sock.connect((self.host,self.port))
      return True
    except socket.error as msg:
      print("Socket Error : %s" % msg)
      return False

  def send(self,data):
    #print('Sending data of size ',len(data))
    self.sock.send(data)
    #print('Data sent!!')

  def receive(self,size=1024):
    #print('Receiving data...')
    return self.sock.recv(size)

  def close(self):
    self.sock.close()

  def __str__(self):
    return 'Client connected to Host='+str(self.host)+',Port='+str(self.port)
