from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58, SIGHASH_ALL
from io import BytesIO
from tx import Tx, TxIn, TxOut
from script import Script, p2pkh_script

# Two nodes between which the channel will be created

nodeA = BTC_node(b'nodeA')
nodeB = BTC_node(b'nodeB')


'''FUNDING TRANSACTION '''

# Node A constructs the input to the transaction
input_tx_id = 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
input_tx_index = 1
tx_in = TxIn(bytes.fromhex(input_tx_id), input_tx_index)
amount = tx_in.value()

# Construct the output: amount, scriptPubKey = 2-of-2 Bare Multisig  = Script([op_1, pubkey1, pubkey2, op_2, op_checkmultisig])
scriptPubKey = Script([0x52, nodeA.public_key.sec(), nodeB.public_key.sec(), 0x52, 0xae])
tx_out = TxOut(amount = amount, script_pubkey = scriptPubKey)

# Construct the transaction object
funding_tx = Tx(1, [tx_in], [tx_out], 0, True)

# Sign the input
funding_tx.sign_input(0, nodeA.private_key)
print(funding_tx.verify())


''' COMMITMENT TRANSACTION '''
#for example: A pays B 1 satoshi

# Create input using the output from the funding tx
tx_in = TxIn(bytes.fromhex(funding_tx.id()), 0)

# Create 2 outputs. 1 to nodeA and 1 to nodeB
script_A = p2pkh_script(decode_base58(nodeA.address))
tx_out_A = TxOut(amount = amount-1, script_pubkey = script_A)

script_B = p2pkh_script(decode_base58(nodeB.address))
tx_out_B = TxOut(amount = 1, script_pubkey = script_B)

# Construct the commitment tx object
commitment_tx = Tx(1, [tx_in], [tx_out_A, tx_out_B], 0, True)
z = commitment_tx.sig_hash(0)

# let A sign the multisig
signatureA = nodeA.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
script_sig = Script([0x0, signatureA])
commitment_tx.tx_ins[0].script_sig = script_sig

print(commitment_tx.verify())

# let B sign the multisig as well
signatureB = nodeB.private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
script_sig = Script([0x0, signatureA, signatureB])
commitment_tx.tx_ins[0].script_sig = script_sig

print(commitment_tx.verify())

print(commitment_tx)




















