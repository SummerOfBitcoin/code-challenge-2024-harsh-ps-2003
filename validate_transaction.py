import binascii
import struct
import json
from typing import List, Dict
import hashlib
# import ecdsa
from ripemd.ripemd160 import ripemd160
# import bech32
# import base58

SIGHASH_ALL = b'\x01'
SIGHASH_ANYONECANPAY = b'\x80'

OP_0 = b'\x00'
OP_PUSHNUM_1 = b'\x01'
# Define the raw transaction data
raw_transaction = """
{
  "txid": "5ae5be014ba43d0054e9e5a8028cef55ef765733fc42c58d91985c4a1a95c980",
  "version": 1,
  "locktime": 0,
  "vin": [
    {
      "txid": "d0c0b3f4a4768e7103a1237393a2b0a6d09797c46692a804407e2790de67bd66",
      "vout": 1,
      "prevout": {
        "scriptpubkey": "76a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 9f21a07a0c7c3cf65a51f586051395762267cdaf OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1FWQiwK27EnGXb6BiBMRLJvunJQZZPMcGd",
        "value": 106383179
      },
      "scriptsig": "4730440220521c8b3f37a59b88fcca25910cdf97d57b1145916380b064ab11c39434560550022003aed791b6515868cb8ba797d329987e44b7e62e0b01731ef799516fb53697e001210369e03e2c91f0badec46c9c903d9e9edae67c167b9ef9b550356ee791c9a40896",
      "scriptsig_asm": "OP_PUSHBYTES_71 30440220521c8b3f37a59b88fcca25910cdf97d57b1145916380b064ab11c39434560550022003aed791b6515868cb8ba797d329987e44b7e62e0b01731ef799516fb53697e001 OP_PUSHBYTES_33 0369e03e2c91f0badec46c9c903d9e9edae67c167b9ef9b550356ee791c9a40896",
      "is_coinbase": false,
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "scriptpubkey": "76a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac",
      "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 9f21a07a0c7c3cf65a51f586051395762267cdaf OP_EQUALVERIFY OP_CHECKSIG",
      "scriptpubkey_type": "p2pkh",
      "scriptpubkey_address": "1FWQiwK27EnGXb6BiBMRLJvunJQZZPMcGd",
      "value": 6377179
    },
    {
      "scriptpubkey": "76a9140869ef31e55ac93f6689c348d687a046616ec65788ac",
      "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 0869ef31e55ac93f6689c348d687a046616ec657 OP_EQUALVERIFY OP_CHECKSIG",
      "scriptpubkey_type": "p2pkh",
      "scriptpubkey_address": "1mVJyziKNhgw9Q5W1YvjcHm6Z4bjX9Ckg",
      "value": 100000000
    }
  ],
  "size": 225,
  "weight": 900,
  "fee": 6000,
  "status": {
    "confirmed": true,
    "block_height": 834638,
    "block_hash": "000000000000000000025f742c626208ac87e0b7d15054abb4a19ca2d735a54e",
    "block_time": 1710405325
  },
  "hex": "010000000166bd67de90277e4004a89266c49797d0a6b0a2937323a103718e76a4f4b3c0d0010000006a4730440220521c8b3f37a59b88fcca25910cdf97d57b1145916380b064ab11c39434560550022003aed791b6515868cb8ba797d329987e44b7e62e0b01731ef799516fb53697e001210369e03e2c91f0badec46c9c903d9e9edae67c167b9ef9b550356ee791c9a40896ffffffff02db4e6100000000001976a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac00e1f505000000001976a9140869ef31e55ac93f6689c348d687a046616ec65788ac00000000"
}
"""

def verify_transaction(transaction_data: Dict, filename:str) -> bool:
    vin = transaction_data.get('vin', [])
    vout = transaction_data.get('vout', [])

    # Validate inputs and outputs
    if validate_inputs(vin, vout) < 0:
        return False

    if not verify_unlocking_script(vin, vout, filename): 
        return False

    return True

def validate_inputs(vin: List[Dict], vout: List[Dict]) -> int:
    #Validate that the sum of input values is greater than or equal to the sum of output values, preventing the creation of bitcoins out of thin air.

    # Calculate sum of input values
    input_sum = sum([vin_entry.get('prevout', {}).get('value', 0) for vin_entry in vin])

    # Calculate sum of output values
    output_sum = sum([vout_entry.get('value', 0) for vout_entry in vout])

    # Ensure input sum is greater than or equal to output sum
    return input_sum - output_sum # diff is fee

# def serialize_transaction_txid(tx: Dict, tx_input_index: int) -> str:
#     def int_to_little_endian(value: int, length: int) -> bytes:
#         """Convert integer to little endian bytes of specified length."""
#         return value.to_bytes(length, byteorder='little')

#     def varint(n: int) -> bytes:
#         """Encode number as varint."""
#         if n < 0xfd:
#             return int_to_little_endian(n, 1)
#         elif n <= 0xffff:
#             return b'\xfd' + int_to_little_endian(n, 2)
#         elif n <= 0xffffffff:
#             return b'\xfe' + int_to_little_endian(n, 4)
#         else:
#             return b'\xff' + int_to_little_endian(n, 8)

#     serialized_tx = b''

#     # Serialize transaction version (little endian)
#     serialized_tx += int_to_little_endian(tx['version'], 4)

#     # Serialize number of inputs (as single byte)
#     serialized_tx += varint(len(tx['vin']))

#     # Iterate over each input
#     for input_index, vin in enumerate(tx['vin']):
#         # Reverse txid bytes
#         txid_bytes_reversed = bytearray.fromhex(vin['txid'])[::-1]
        
#         # Append txid (reversed)
#         serialized_tx += txid_bytes_reversed
        
#         # Append vout (little endian)
#         serialized_tx += int_to_little_endian(vin['vout'], 4)

#         # Append scriptSig length or 0 if not the current input
#         if input_index == tx_input_index:
#             scriptSig_bytes = bytes.fromhex(vin.get('scriptsig', ''))
#             serialized_tx += varint(len(scriptSig_bytes)) + scriptSig_bytes
#         else:
#             serialized_tx += b'\x00'

#         # Append sequence (little endian)
#         serialized_tx += int_to_little_endian(vin['sequence'], 4)

#     # Serialize number of outputs (as single byte)
#     serialized_tx += varint(len(tx['vout']))

#     # Iterate over each output
#     for tx_output in tx['vout']:
#         # Append output value (little endian)
#         serialized_tx += int_to_little_endian(tx_output['value'], 8)

#         # Decode scriptPubKey bytes from hex
#         script_pubkey_bytes = bytes.fromhex(tx_output['scriptpubkey'])

#         # Append scriptPubKey length (as varint)
#         serialized_tx += varint(len(script_pubkey_bytes))

#         # Append scriptPubKey bytes
#         serialized_tx += script_pubkey_bytes

#     # Serialize locktime (little endian)
#     serialized_tx += int_to_little_endian(tx['locktime'], 4)

#     return serialized_tx.hex()

# def verify_txid(transaction_data: Dict, currentvin: Dict, filename: str) -> bool:
#     serialized_transaction = bytes.fromhex(serialize_transaction_txid(transaction_data, currentvin))
#     hashed_serialized_transaction = hashlib.sha256(hashlib.sha256(serialized_transaction).digest()).digest()
#     return filename == hashlib.sha256(hashed_serialized_transaction[::-1]).digest().hex()

# def verify_signatures(pubkey_bytes: any, signature_bytes: any, transaction_data: Dict, currentvin: Dict, filename: str) -> bool:
#     # Load the public key
#     vins = transaction_data.get('vin', [])
#     for vin in vins:
#       txid = vin.get('txid')
#       if vin == currentvin:
#           # Replace scriptSig with previous scriptPubKey (including length)
#           vin['scriptsig'] = vin['prevout']['scriptpubkey']
#       else:
#           # Replace scriptSig with just the length byte set at 00
#           vin['scriptSig'] = None
#     try:
#         vk = ecdsa.VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.SECP256k1, hashfunc = hashlib.sha256)
#     except ValueError:
#         return False

#         sighash_bytes = signature_bytes[-1:]
#         signature = signature_bytes[:-1]
#         if sighash_bytes == SIGHASH_ALL:
#             data = transaction_data
#         elif sighash_bytes == SIGHASH_ANYONECANPAY:
#             data = transaction_data
#             data['vin'] = currentvin

#         # Concatenate SIGHASH type and hash the serialized transaction using SHA256 twice
#         serialized_txn = bytes.fromhex(serialize_transaction(data, currentvin))
#         preimage = (hashlib.sha256(serialized_txn + sighash_bytes).digest())
#         hashed_serialized_txn = hashlib.sha256(preimage).digest()

#         try:
#             # Verify the signature against the hashed transaction
#             return vk.verify(signature, hashed_serialized_txn, hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)
#         except ecdsa.BadSignatureError:
#             return False
#     return False

# def verify_signature(txn: str) -> bool:
#     tx = Transaction.parse(txn.encode())
#     # Segwit
#     for input_index, txin in enumerate(tx.inputs()):
#         for witness_index, witness in enumerate(txin.witness):
#             key = Key(witness)
#             if not tx.verify_input_signature(input_index, key.pubkey, witness_index):
#                 return False
#             return True

#     # For non-SegWit transactions
#     for input_index, txin in enumerate(tx.inputs()):
#         key = Key(txin.script_sig)
#         if not tx.verify_input_signature(input_index, key.pubkey):
#             return False
#         return True
    
def verify_scriptpubkey(data: Dict, witness: List) -> bool:
    scriptpubkey_asm = data.get('prevout')["scriptpubkey_asm"]
    scriptpubkey_address = data.get('prevout')["scriptpubkey_address"]
    scriptpubkey_type = data.get('prevout')["scriptpubkey_type"]
    if scriptpubkey_type == 'p2pkh':
        pubkey_hash = scriptpubkey_asm.split(" ")[3]
        script_pubkey_bytecode = bytes.fromhex(pubkey_hash)
        return base58.b58encode(script_pubkey_bytecode) == scriptpubkey_address
    elif scriptpubkey_type == "v0_p2wpkh" or "v0_p2wsh":
        version = 0
        pubkey_or_script_hash = scriptpubkey_asm.split(" ")[-1]
        try:
            bytecode = bytes.fromhex(pubkey_or_script_hash)
        except ValueError:
            return False
        encoded = bech32.encode('bc', version, bytecode) 
        return encoded == scriptpubkey_address
    elif scriptpubkey_type == 'p2sh':
        pass

def verify_unlocking_script(vin: List[Dict], vout: List[Dict], filename: str) -> bool:
    for data in vin:
        scriptsig = data.get('scriptsig')
        scriptsig_asm = data.get('scriptsig_asm')
        scriptpubkey_asm = data.get('prevout')["scriptpubkey_asm"] 
        witness = data.get('witness', [])
        if verify_scriptpubkey(data, witness) == False:
            return False
        # For P2WPKH (Pay-to-Witness-Public-Key-Hash)
        if len(witness) == 2:
            pubkey_hash = scriptpubkey_asm.split(" ")[-1]
            public_key = witness[1]
            signature = witness[0]
            if public_key:
              hashed_public_key_sha256 = hashlib.sha256(bytes.fromhex(public_key)).digest()
              hashed_public_key_ripemd160 = ripemd160(hashed_public_key_sha256)
              hashed_public_key_ripemd160_hex = binascii.hexlify(hashed_public_key_ripemd160).decode()
              if hashed_public_key_ripemd160_hex == pubkey_hash:
                #   return verify_signature(raw_transaction)
                return True
        # For P2WSH (Pay-to-Witness-Script-Hash)
        elif len(witness) > 2:
            script = witness[-1]
            hashed_redeem_script = scriptpubkey_asm.split(" ")[-1]
            if hashed_redeem_script == hashlib.sha256(bytes.fromhex(script)).hexdigest():
                return True
            else:
                return False
        # dealing with the compressed redeem script in p2sh-p2wsh inputs (last element in the witness), could not identify the opcodes.
        # tranasaction input contains both scriptsig and witness, in case of scriptpubkey_type of p2sh or p2pkh, will it be invalid or valid # If any input has an invalid unlocking script

        if scriptsig:
            publickey = scriptsig_asm.split(" ")[-1]
            signature = scriptsig_asm.split(" ")[1]
            public_key_hash = scriptpubkey_asm.split(" ")[-3]
            hashed_public_key_sha256 = hashlib.sha256(bytes.fromhex(publickey)).digest()
            hashed_public_key_ripemd160 = ripemd160(hashed_public_key_sha256)
            hashed_public_key_ripemd160_hex = binascii.hexlify(hashed_public_key_ripemd160).decode()
            if hashed_public_key_ripemd160_hex != public_key_hash:
                return False  # If any input has an invalid unlocking script

    return True  # All inputs have valid unlocking scripts

def serialize_varint(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + struct.pack('<H', value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', value)
    else:
        return b'\xff' + struct.pack('<Q', value)

def get_raw_transaction(tx, txid):
    is_legacy = all("witness" not in input for input in tx["vin"])

    if is_legacy:
        return None
    else:
        # raw_wtx = bytearray()
        # raw_wtx.extend(tx["version"].to_bytes(4, 'little'))
        # raw_wtx.append(0)  # Marker
        # raw_wtx.append(1)  # Flag

        # raw_wtx.append(len(tx["vin"]))
        # for input in tx["vin"]:
        #     txid = bytes.fromhex(input["txid"])
        #     script_sig = bytes.fromhex(input.get("scriptsig", ""))
        #     script_sig_len = len(script_sig)

        #     raw_wtx.extend(txid)
        #     raw_wtx.extend(input["vout"].to_bytes(4, 'little'))
        #     raw_wtx.append(script_sig_len)
        #     if script_sig_len != 0:
        #         raw_wtx.extend(script_sig)
        #     raw_wtx.extend(input["sequence"].to_bytes(4, 'little'))

        # raw_wtx.append(len(tx["vout"]))
        # for output in tx["vout"]:
        #     scriptpubkey = bytes.fromhex(output["scriptpubkey"])
        #     scriptpubkey_len = len(scriptpubkey)

        #     raw_wtx.extend(output["value"].to_bytes(8, 'little'))
        #     raw_wtx.append(scriptpubkey_len)
        #     raw_wtx.extend(scriptpubkey)

        # raw_wtx.append(len(tx.get("witness", [])))
        # for input in tx["vin"]:
        #     witness = input.get("witness", [])
        #     for item in witness:
        #         item_bytes = bytes.fromhex(item)
        #         item_bytes_len = len(item_bytes)
        #         raw_wtx.append(item_bytes_len)
        #         raw_wtx.extend(item_bytes)

        # raw_wtx.extend(tx["locktime"].to_bytes(4, 'little'))
        # return raw_wtx
        serialized = bytearray()
        # Serialize version
        serialized += struct.pack('<I', tx['version'])
        serialized += bytes([0x00, 0x01])
        vin_count = len(tx['vin'])
        serialized += serialize_varint(vin_count)
        # Serialize vin
        for vin in tx['vin']:
            txid_bytes = binascii.unhexlify(vin['txid'])
            serialized += txid_bytes[::-1]

            vout_bytes = struct.pack('<I', vin['vout'])
            serialized += vout_bytes

            scriptsig_bytes = binascii.unhexlify(vin['scriptsig'])
            serialized += serialize_varint(len(scriptsig_bytes))
            serialized += scriptsig_bytes

            sequence_bytes = struct.pack('<I', vin['sequence'])
            serialized += sequence_bytes
            # Serialize vout count
            vout_count = len(tx['vout'])
            serialized += serialize_varint(vout_count)

        # Serialize vout
        for vout in tx['vout']:
                value_bytes = struct.pack('<Q', vout['value'])
                serialized += value_bytes

                scriptpubkey_bytes = binascii.unhexlify(vout['scriptpubkey'])
                serialized += serialize_varint(len(scriptpubkey_bytes))
                serialized += scriptpubkey_bytes
        for vin in tx['vin']:
                witness_count = len(vin['witness'])
                serialized += serialize_varint(witness_count)
                for witness in vin['witness']:
                    witness_bytes = binascii.unhexlify(witness)
                    serialized += serialize_varint(len(witness_bytes))
                    serialized += witness_bytes

        locktime_bytes = struct.pack('<I', tx['locktime'])
        serialized += locktime_bytes
        return bytes(serialized)

# verify_transaction(json.loads(raw_transaction), 'fff4a0b689cc3f6d03be29f58c0f68fc136a5d71175351230fcfe6662bebfce4')
# print(get_raw_transaction(json.loads(raw_transaction)).hex())