from io import BytesIO
import sys
#from bitcoin.rpc import RawProxy
from ecc import PrivateKey
from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    SIGHASH_ALL,
)

from script import p2pkh_script, Script

class TxFetcher:

    @classmethod
    def fetch(cls, tx_id, testnet=False):
        if testnet:
            p = RawProxy(service_port = 18332)
            raw_tx =bytes.fromhex(p.getrawtransaction(tx_id))
            tx = Tx.parse(BytesIO(raw_tx), testnet = testnet)
            return tx
        return None


class Tx:
    command = b'tx'

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for i, tx_in in enumerate(self.tx_ins, start = 0):
            tx_ins+= str(i)+":\t"+tx_in.__repr__() + '\n'
        tx_outs = ''
        for i, tx_out in enumerate(self.tx_outs, start=0):
            tx_outs += str(i)+":\t"+tx_out.__repr__() + '\n'

        s = "\n==============================Transaction Info ==================================\n"
        s += "TxID:     " + str(self.id())
        s += "\nVersion:  " + str(self.version)
        s += "\nTx_ins:\n" + tx_ins
        s += "\nTx_outs:\n"+ tx_outs
        s += "\nLocktime:"+ str(self.locktime)
        s += "\nTotal Fee: " + str(self.fee())
        s += "\n=================================================================================\n"
        return s


    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))
        marker = s.read(2)
        if marker != b'\x00\x01':  # <1>
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        for tx_in in inputs:  # <2>
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness = items
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime,
                   testnet=testnet, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):  # <1>
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        result = int_to_little_endian(self.version, 4)
        result += b'\x00\x01'
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        for tx_in in self.tx_ins:
            result += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None
            s += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, 'big')

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_sequence = hash256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).cmds[1]).serialize()
        s += script_code
        s += int_to_little_endian(tx_in.value(testnet = self.testnet), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(s), 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # grab the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the ScriptPubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last cmd has to be the RedeemScript to trigger
            cmd = tx_in.script_sig.cmds[-1]
            # parse the RedeemScript
            raw_redeem = int_to_little_endian(len(cmd), 1) + cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
            # the RedeemScript might be p2wpkh or p2wsh
            if redeem_script.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness
            elif redeem_script.is_p2wsh_script_pubkey():
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            # ScriptPubkey might be a p2wpkh or p2wsh
            if script_pubkey.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index)
                witness = tx_in.witness
            elif script_pubkey.is_p2wsh_script_pubkey():
                cmd = tx_in.witness[-1]
                raw_witness = encode_varint(len(cmd)) + cmd
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index)
                witness = None
        # combine the current ScriptSig and the previous ScriptPubKey
        combined = tx_in.script_sig + script_pubkey
        # evaluate the combined script
        return combined.evaluate(z, witness)

    def verify(self):
        '''Verify this transaction'''
        # check that we're not creating money
        if self.fee() < 0:
            return False
        # check that each input has a valid ScriptSig
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self, input_index, private_key):
        '''Signs the input using the private key'''
        z = self.sig_hash(input_index)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.point.sec()
        script_sig = Script([sig, sec])
        self.tx_ins[input_index].script_sig = script_sig
        return self.verify_input(input_index)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        if len(self.tx_ins) != 1:
            return False
        first_input = self.tx_ins[0]
        if first_input.prev_tx != b'\x00' * 32:
            return False
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        if not self.is_coinbase():
            return None
        first_cmd = self.tx_ins[0].script_sig.cmds[0]
        return little_endian_to_int(first_cmd)


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        ''' return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )'''
        s = str(self.prev_tx.hex())+":"+str(self.prev_index)+"\n"
        s += "\tScriptPubKey: "+str(self.script_pubkey(testnet = True))+"\n"
        s += "\tScriptSig:  "+str(self.script_sig)+"\n"
        s += "\tAmount: "+str(self.value(testnet = True))
        return s

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        #tx = self.fetch_tx(testnet=testnet)
        #return tx.tx_outs[self.prev_index].amount

        if self.prev_tx==bytes.fromhex('d4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101e1358b8ced4557e494aae062fcf1705ffe2f8938ed4b249d6f92568cdd55a7fb0000000017160014dec6d56b9d27456479719aa01b61f58b615ad591feffffff02319010000000000017a91478255173b20875021a24ddfa9cf602a393eeed28879fbb0d00000000001976a91487a2d933c4bb2c005628dcdd33cb7d09ba36dcd688ac02473044022071cf3cf8a75065a91ed3fd6e3f562925969978f9f2608aad6ddfa15d95cdf9d2022046da872f4796402a4a21d1aa4cae6dfe13f7dccaf99a2d9a35a48a85dfdf10a1012103db89338f5ccca48baf6ab270b920194a0ee590227f037f04cfbd72687d102017a3091800'))).tx_outs[1].amount
        if self.prev_tx==bytes.fromhex('e8dfc8ccf59e1a62b06b7d6fdd93ca74e1d9dedb843408731c9253b07a397884'):
            return Tx.parse(BytesIO(bytes.fromhex('0100000001bcd6c913d178b84260e6a5de59072efcefbfdf581942a0ac972c41c45373f3d4010000006b483045022100d36b463dbc9f6c08d2c4ebbf5f39a9f78e9acd82ca105120395fb8435385f67402206ad19c614575e0aa84f6ac051353db5c50417a245b1df23e7093134368c642d8012103ad993951e9b6f565256f5c6907fbd42c0f2bf5dd5f803531c9d0a6eacbfaba86ffffffff019fbb0d000000000047522103ad993951e9b6f565256f5c6907fbd42c0f2bf5dd5f803531c9d0a6eacbfaba862103287147939b886ecffc4f8168f0f05eb67b668bfe15dc494fb4da28208188d3cb52ae00000000'))).tx_outs[0].amount
        if self.prev_tx==bytes.fromhex('77535a39b5397a851539d4381ce3000bb5932ef6d7857e9c6e3e1aed6dd43216'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101de1eff388b0c0467044466c23b98177b019baf6707d0ffadbbe7aad18220072601000000171600147fc1cc2511e91324276a2726ec447fde0a8bcedcfeffffff029fbb0d00000000001976a91404b26bc2368f79b3c265f0723d7d2f128275d45088ac7aa510000000000017a914c7385ef00b053d5386855a057a2a0a651c3882208702473044022058f010d5353542c94d8c5f9f620b704ae7725a0ee0e973e7e59699f2a9347f110220228f73c5c0df3a865b8bc6ba7661e0a5c13afd2440da34af0cb0ec312aab208e012103b65b480f81de21d841ee0c654570cff753b821c43085dbd1f658a67807062081a3091800'))).tx_outs[0].amount
        if self.prev_tx==bytes.fromhex('e49a74f9b24d75b8e168b90b0d3eb930d11b3a387a2380343f159431bbb43d62'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101a3912f608faa606c7a65b6ec03a01212c693b2bc68cdffd97dfca3999ae38a020100000017160014cd2889f7ffd494506cafe1ed2dba1ed33831419bfeffffff029fbb0d00000000001976a9144563df454b8b793145a06be36de0afc2ee0ed06b88ac824410000000000017a9147a761f6a032bf81bd1945cad5e725391da7957c787024730440220369ae824d465a55695ebbb37d9e9420836d0340456a200998e6b3624c6b76fcf02204e529490b2199149c4b6894ef9b8a3965755dfd1fe728ad2be82290f9ad429b30121021b7e8e802cd0e7e9206f166f23024aa87b2ae7c372a5212d83d3999de8edabcaa4091800'))).tx_outs[0].amount
        if self.prev_tx==bytes.fromhex('15fccae87a15395af0232ba7e1a5659a6d3ca67c90ebdf900025753fb6a57f3e'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101836fc8e10491dd3e8bad1c4cb5528da6bf0c029a2c23bff97e96d7dde4b382b40d000000171600141875f21917cf029ae103d125c45812b79c90e8e9feffffff029fbb0d00000000001976a91487a2d933c4bb2c005628dcdd33cb7d09ba36dcd688ac1d2d32000000000017a9147875771138e64ff5786217b4c55589656f06c931870247304402205f193f5c83ab6bf7e2cde21600ebcdab1771af8cd7cad16866a018e5c5da9e1d02203f1005a1eec6207064362fdc72cad04cc6791ddf884e49649383a76de72c826b012103e6a8bf960187331d6dbed038de45cbdacba375aa86c784d15f6589d2ed1dc5310c0e1800'))).tx_outs[0].amount


    def script_pubkey(self, testnet=False):
        '''Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        #tx = self.fetch_tx(testnet=testnet)
        #return tx.tx_outs[self.prev_index].script_pubkey


        if self.prev_tx==bytes.fromhex('d4f37353c4412c97aca0421958dfbfeffc2e0759dea5e66042b878d113c9d6bc'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101e1358b8ced4557e494aae062fcf1705ffe2f8938ed4b249d6f92568cdd55a7fb0000000017160014dec6d56b9d27456479719aa01b61f58b615ad591feffffff02319010000000000017a91478255173b20875021a24ddfa9cf602a393eeed28879fbb0d00000000001976a91487a2d933c4bb2c005628dcdd33cb7d09ba36dcd688ac02473044022071cf3cf8a75065a91ed3fd6e3f562925969978f9f2608aad6ddfa15d95cdf9d2022046da872f4796402a4a21d1aa4cae6dfe13f7dccaf99a2d9a35a48a85dfdf10a1012103db89338f5ccca48baf6ab270b920194a0ee590227f037f04cfbd72687d102017a3091800'))).tx_outs[1].script_pubkey
        if self.prev_tx==bytes.fromhex('e8dfc8ccf59e1a62b06b7d6fdd93ca74e1d9dedb843408731c9253b07a397884'):
            return Tx.parse(BytesIO(bytes.fromhex('0100000001bcd6c913d178b84260e6a5de59072efcefbfdf581942a0ac972c41c45373f3d4010000006b483045022100d36b463dbc9f6c08d2c4ebbf5f39a9f78e9acd82ca105120395fb8435385f67402206ad19c614575e0aa84f6ac051353db5c50417a245b1df23e7093134368c642d8012103ad993951e9b6f565256f5c6907fbd42c0f2bf5dd5f803531c9d0a6eacbfaba86ffffffff019fbb0d000000000047522103ad993951e9b6f565256f5c6907fbd42c0f2bf5dd5f803531c9d0a6eacbfaba862103287147939b886ecffc4f8168f0f05eb67b668bfe15dc494fb4da28208188d3cb52ae00000000'))).tx_outs[0].script_pubkey
        if self.prev_tx==bytes.fromhex('77535a39b5397a851539d4381ce3000bb5932ef6d7857e9c6e3e1aed6dd43216'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101de1eff388b0c0467044466c23b98177b019baf6707d0ffadbbe7aad18220072601000000171600147fc1cc2511e91324276a2726ec447fde0a8bcedcfeffffff029fbb0d00000000001976a91404b26bc2368f79b3c265f0723d7d2f128275d45088ac7aa510000000000017a914c7385ef00b053d5386855a057a2a0a651c3882208702473044022058f010d5353542c94d8c5f9f620b704ae7725a0ee0e973e7e59699f2a9347f110220228f73c5c0df3a865b8bc6ba7661e0a5c13afd2440da34af0cb0ec312aab208e012103b65b480f81de21d841ee0c654570cff753b821c43085dbd1f658a67807062081a3091800'))).tx_outs[0].script_pubkey
        if self.prev_tx==bytes.fromhex('e49a74f9b24d75b8e168b90b0d3eb930d11b3a387a2380343f159431bbb43d62'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101a3912f608faa606c7a65b6ec03a01212c693b2bc68cdffd97dfca3999ae38a020100000017160014cd2889f7ffd494506cafe1ed2dba1ed33831419bfeffffff029fbb0d00000000001976a9144563df454b8b793145a06be36de0afc2ee0ed06b88ac824410000000000017a9147a761f6a032bf81bd1945cad5e725391da7957c787024730440220369ae824d465a55695ebbb37d9e9420836d0340456a200998e6b3624c6b76fcf02204e529490b2199149c4b6894ef9b8a3965755dfd1fe728ad2be82290f9ad429b30121021b7e8e802cd0e7e9206f166f23024aa87b2ae7c372a5212d83d3999de8edabcaa4091800'))).tx_outs[0].script_pubkey
        if self.prev_tx==bytes.fromhex('15fccae87a15395af0232ba7e1a5659a6d3ca67c90ebdf900025753fb6a57f3e'):
            return Tx.parse(BytesIO(bytes.fromhex('02000000000101836fc8e10491dd3e8bad1c4cb5528da6bf0c029a2c23bff97e96d7dde4b382b40d000000171600141875f21917cf029ae103d125c45812b79c90e8e9feffffff029fbb0d00000000001976a91487a2d933c4bb2c005628dcdd33cb7d09ba36dcd688ac1d2d32000000000017a9147875771138e64ff5786217b4c55589656f06c931870247304402205f193f5c83ab6bf7e2cde21600ebcdab1771af8cd7cad16866a018e5c5da9e1d02203f1005a1eec6207064362fdc72cad04cc6791ddf884e49649383a76de72c826b012103e6a8bf960187331d6dbed038de45cbdacba375aa86c784d15f6589d2ed1dc5310c0e1800'))).tx_outs[0].script_pubkey


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)


    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


