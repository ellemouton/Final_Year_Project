from socket_helper import SocketError, SocketClient
from general_helper import *
from time import sleep
from ecc import S256Point
from helper import sha256, decode_base58
from io import BytesIO
from tx import Tx, TxIn, TxOut

#create BTC address. secret -> private key -> public key
node = BTC_node(b'nodeA')
print("Node Bitcoin Address: "+str(node.address))

tx_in_id= 'd4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'
tx_in_index = 1
#tx_out = Tx.parse(BytesIO(bytes.fromhex('02000000000101e1358b8ced4557e494aae062fcf1705ffe2f8938ed4b249d6f92568cdd55a7fb0000000017160014dec6d56b9d27456479719aa01b61f58b615ad591feffffff02319010000000000017a91478255173b20875021a24ddfa9cf602a393eeed28879fbb0d00000000001976a91487a2d933c4bb2c005628dcdd33cb7d09ba36dcd688ac02473044022071cf3cf8a75065a91ed3fd6e3f562925969978f9f2608aad6ddfa15d95cdf9d2022046da872f4796402a4a21d1aa4cae6dfe13f7dccaf99a2d9a35a48a85dfdf10a1012103db89338f5ccca48baf6ab270b920194a0ee590227f037f04cfbd72687d102017a3091800'))).tx_outs[1]
#on_chain_amount = tx_out.amount
#tx_script = tx_out.script_pubkey


#construct input
tx_in = TxIn(bytes.fromhex(tx_in_id), tx_in_index)
print(tx_in)

#construct output
target_address = ""
target_h160 = decode_base58(target_address)
target_amount = tx_in.value()
target_script = p2sh_script(0)
tx_out = TxOut(amount= target_amount, script_pubkey = target_script)

#construct transaction

#sign inputs

#verify transaction






















