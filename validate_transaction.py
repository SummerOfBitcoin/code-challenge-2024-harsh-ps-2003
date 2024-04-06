import binascii
import json
from typing import List, Dict
import hashlib
# import ecdsa
from ripemd.ripemd160 import ripemd160
import bech32
import base58

SIGHASH_ALL = b'\x01'
SIGHASH_ANYONECANPAY = b'\x80'

OP_0 = b'\x00'
OP_PUSHNUM_1 = b'\x01'
# Define the raw transaction data
raw_transaction = """
{
        "version": 2,
        "locktime": 834637,
        "vin": [
            {
                "txid": "d0fa3356fb263009d4fc8d7d6ba59963a560baba8da03501fdc411ff26b76ad6",
                "vout": 4,
                "prevout": {
                    "scriptpubkey": "0014371c620e2a5f79132ddea30020e251ddab5e315f",
                    "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 371c620e2a5f79132ddea30020e251ddab5e315f",
                    "scriptpubkey_type": "v0_p2wpkh",
                    "scriptpubkey_address": "bc1qxuwxyr32tau3xtw75vqzpcj3mk44uv2lwv5gtu",
                    "value": 68200
                },
                "scriptsig": "",
                "scriptsig_asm": "",
                "witness": [
                    "30440220323ad83e9b1c3d3d1f8704f507a044e2a174fc04fa3936f8a0e9f238c0ea7b9102203852a5543a0907d41c79ee6b6750b2a31d43c5632ceaa31aa379defc2edf845b01",
                    "035ef2f94376edda64a2edb2acb257b44ab055b336f7e92c5a269144867d39a854"
                ],
                "is_coinbase": false,
                "sequence": 4294967293
            }
        ],
        "vout": [
            {
                "scriptpubkey": "0014c3f0446c20163f8bf338aea7db72b637ce23ff0f",
                "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 c3f0446c20163f8bf338aea7db72b637ce23ff0f",
                "scriptpubkey_type": "v0_p2wpkh",
                "scriptpubkey_address": "bc1qc0cygmpqzclchuec46naku4kxl8z8lc0r3cn5e",
                "value": 1500
            },
            {
                "scriptpubkey": "a914a077ab3315cc4c61c780fbc1ebaf92adf9b0b9dc87",
                "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 a077ab3315cc4c61c780fbc1ebaf92adf9b0b9dc OP_EQUAL",
                "scriptpubkey_type": "p2sh",
                "scriptpubkey_address": "3GKVPy3J86HQmNK6rwwaxZjzKvYiRBE4wE",
                "value": 59600
            }
        ]
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

verify_transaction(json.loads(raw_transaction), 'fff4a0b689cc3f6d03be29f58c0f68fc136a5d71175351230fcfe6662bebfce4')