from ecc import PrivateKey, G
from helper import hash256, little_endian_to_int
from general_helper import BTC_node
import sys

'''
Got this method from:
https://bitcointalk.org/index.php?topic=685269.0
'''


def xor(var, key):
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)

def encrypt(message, key):
	return xor(message, key)

def decrypt(message, key):
	return xor(message, key)

# NODE A
nodeA = BTC_node(b'nodeA')
print(nodeA.address)


# NODE B
nodeB = BTC_node(b'nodeB')
print(nodeB.address)


# Node A
sym_key_A = nodeA.secret*nodeB.public_key
print(sym_key_A)

message = b'Testing testing'
encrypted_message = encrypt(message, sym_key_A.sec())


# Node B
sym_key_B = nodeB.secret*nodeA.public_key
decrypted_message = decrypt(encrypted_message, sym_key_B.sec())
print(decrypted_message)




