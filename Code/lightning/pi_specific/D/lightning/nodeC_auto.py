from socket_helper import SocketError, SocketServer
from general_helper import *
from time import sleep 
from ecc import S256Point
import json
import threading

global peers

peers = []
channels = []

host = '127.0.0.1'
port = 3000

def sockB_checker():
  while True:
    prev_hop = get_peer(peers, 'mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn')
    sym_key_1 = node.secret*prev_hop.public_key

    # receive header
    received_header = prev_hop.receive()
    decrypted_header = json.loads(decrypt(received_header, sym_key_1.sec()).decode())
    source = get_peer(peers, decrypted_header['source'])
    cost_paid = route_cost(decrypted_header['route'])

    prev_hop.send(b'header ACK')

    #receive body
    sym_key_2 = node.secret*source.public_key
    encrypted_body = prev_hop.receive()
    decrypted_message = json.loads(decrypt(encrypted_body, sym_key_2.sec()).decode())
    secret = decrypted_message['secret']

    prev_hop.send(str.encode(secret))
    get_channel(prev_hop, channels).paid(cost_paid)
    print(get_channel(prev_hop, channels))

    print("Total Balance: "+str(get_total_channel_balance(channels)))

def sockD_checker():
  while True:
    prev_hop = get_peer(peers, 'mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW')
    sym_key_1 = node.secret*prev_hop.public_key

    # receive header
    received_header = prev_hop.receive()
    decrypted_header = json.loads(decrypt(received_header, sym_key_1.sec()).decode())
    source = get_peer(peers, decrypted_header['source'])
    cost_paid = route_cost(decrypted_header['route'])

    prev_hop.send(b'header ACK')

    #receive body
    sym_key_2 = node.secret*source.public_key
    encrypted_body = prev_hop.receive()
    decrypted_message = json.loads(decrypt(encrypted_body, sym_key_2.sec()).decode())
    secret = decrypted_message['secret']

    prev_hop.send(str.encode(secret))
    get_channel(prev_hop, channels).paid(cost_paid)
    print(get_channel(prev_hop, channels))

    print("Total Balance: "+str(get_total_channel_balance(channels)))


'''
create BTC address. secret -> private key -> public key
'''
node = BTC_node(b'nodeC')
print("Node Bitcoin Address: "+str(node.address))

'''
advertise price
'''
prices = json.load(open("peer_prices.txt"))
prices[node.address] = 2
json.dump(prices, open("peer_prices.txt",'w'))

'''
Automatically listen for peers A, B and D
'''
# peer B
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer D
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

# peer A
print("Listening on: "+host+":"+str(port)+".....")
peers.append(listen_for_new_peer(host, port, node))
port+=1

for p in peers:
  print(p)

'''
Automatically listen for channels from B and D
'''
channels.append(listen_for_channel_request(peers[0]))
channels.append(listen_for_channel_request(peers[1]))

for c in channels:
  print(c)



print("----Receive Mode----")

sockB = threading.Thread(target=sockB_checker)
sockB.start()

sockD = threading.Thread(target=sockD_checker)
sockD.start()



