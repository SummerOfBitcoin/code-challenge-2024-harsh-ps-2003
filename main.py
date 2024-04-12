import os
import json
import hashlib
from validate_transaction import verify_transaction, validate_inputs, get_raw_transaction
from typing import List, Dict
import time

DIFFICULTY_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
MAX_BLOCK_SIZE = 1000000  # 1 MB
WITNESS_RESERVED_VALUE = b"0000000000000000000000000000000000000000000000000000000000000000"

def read_transactions(mempool_dir: str) -> List[Dict]:
    data = {}
    with open("valid.txt", 'r') as valid:
        valid_filenames = list(set(valid.read().splitlines()))
        valid_filenames = [filename + '.json' for filename in valid_filenames]
    for filename in os.listdir(mempool_dir):
        if (filename in valid_filenames):
            filepath = os.path.join(mempool_dir, filename)
            with open(filepath, 'r') as file:
                transaction_data = json.load(file)
                txid = transaction_data["txid"]
                weight = transaction_data["weight"]
                data[txid] = weight
    sorted_data = sorted(data.items(), key=lambda x: x[1])
    global selected_txids
    selected_txids = []
    total_weight = 988 #coinbase
    for txid, weight in sorted_data:
        if total_weight + weight <= 4000000:
            selected_txids.append(txid)
            total_weight += weight
        else:
            break
    return selected_txids

def create_coinbase_transaction(miner_address: str, block_height: int, block_reward: int, transactions: List[Dict]) -> dict:

    """
    Create a coinbase transaction.

    :param miner_address: The address of the miner to receive the block reward.
    :param block_height: The height of the block being mined.
    :param block_reward: The total block reward (block subsidy + transaction fees).
    :param witness_commitment: The witness commitment hash.
    :return: A dictionary representing the coinbase transaction.
    """
    # Coinbase transaction's input
    vin = [{
        'txid': '0000000000000000000000000000000000000000000000000000000000000000',
        'vout': 0xffffffff,
        'scriptSig': {
            'asm': f'{block_height}',
            'hex': block_height.to_bytes(4, 'little').hex() + '...'  # Placeholder for additional data to ensure scriptSig length is valid
        },
        'sequence': 0xffffffff,
        'coinbase': '...'  # Placeholder for coinbase data (e.g., extra nonce and miner-defined data)
    }]

    # Output for the miner's block reward
    vout_miner_reward = {
        'value': block_reward,
        'scriptPubKey': {
            'asm': f'OP_DUP OP_HASH160 {miner_address} OP_EQUALVERIFY OP_CHECKSIG',
            'hex': '...'  # Placeholder for the actual hex representation
        }
    }

    # Output for the witness commitment
    vout_witness_commitment = {
        'value': 0,
    }

    # The coinbase transaction itself
    coinbase_tx = {
        'version': 4,
        'vin': vin,
        'vout': [vout_miner_reward, vout_witness_commitment],
        'locktime': 0,
        'witness': []  # Empty witness data as it's a coinbase transaction
    }

    # result = get_raw_transaction("segwit", coinbase_tx)
    # serilaized_coinbase_txn = result[1]
    # coinbase_byte = hashlib.sha256(hashlib.sha256(serilaized_coinbase_txn).digest()).digest() 
    # return coinbase_tx, coinbase_byte.hex()
    # wtxids = []
    # # coinbase wtxid
    # wtxids.append("0000000000000000000000000000000000000000000000000000000000000000")
    # other txids
    # for txid in selected_txids:
    #     tx_file = os.path.join("mempool", f"{txid}.json")
    #     with open(tx_file, 'r') as file:
    #         tx = json.load(file)
    #         if all("witness" not in input for input in tx["vin"]):
    #             wtxids.append(txid[::-1]) # if legacy then wtxid = txid
    #         try:
    #             raw_wtx = get_raw_transaction(tx)
    #         except Exception as e:
    #             selected_txids.remove(txid)
    #         wtxids.append(((hashlib.sha256(hashlib.sha256(raw_wtx).digest()).digest())[::-1]).hex())
    # witnessroot = merkleroot(wtxids)
    # concatenated_data = witnessroot.hex() + WITNESS_RESERVED_VALUE.hex()
    # witnessComm = (hashlib.sha256(hashlib.sha256(bytes.fromhex(concatenated_data)).digest()).digest()).hex()
    coinbase_tx_hex = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9edb1f388d2494962d74c661a3a94dc543ba57e6d74ad4174e7f5a663d2d295db960120000000000000000000000000000000000000000000000000000000000000000000000000"
    mid = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase_tx_hex)).digest()).digest()  
    global coinbase_txid
    coinbase_txid = mid[::-1].hex()
    return coinbase_tx_hex

def construct_block(transactions: List[Dict], miner_address: str, block_height: int) -> Dict:
    # Create the coinbase transaction
    global coinbase_tx_hex
    coinbase_tx_hex = create_coinbase_transaction(miner_address, block_height, 50, transactions)  # Assuming a fixed block reward of 50 BTC
    # # Add the coinbase transaction to the beginning of the transactions list
    # transactions.insert(0, coinbase_tx)
    # Construct the block header
    block_header = {
        "version": 4,
        "previous_block_hash": "0"*64,  # Placeholder for the previous block hash
        "merkle_root": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "time": int(time.time()),  # Placeholder for the block's timestamp
        "bits": DIFFICULTY_TARGET,  # Placeholder for the difficulty target
        "nonce": 0  # Placeholder for the nonce
    }

    # Assemble the block
    block = {
        "header": block_header,
        "transactions": transactions
    }

    return block

# def createpreviousblockhash() -> bytes:
#     difficulty_target = bytes.fromhex('0000ffff00000000000000000000000000000000000000000000000000000000')
#     target_int = int.from_bytes(difficulty_target, 'big')
#     greater_hash_int = target_int + 33
#     greater_hash_bytes = greater_hash_int.to_bytes(32, 'big')
#     reversed_hash_bytes = greater_hash_bytes[::-1]
#     return reversed_hash_bytes

# def createmerkleroot(transactions: List[Dict]) -> bytes:
#     # Initialize an empty list to store txids
#     txid_list = []

#     # Iterate over transactions
#     for tx in transactions[1:]:
#         # Iterate over vin fields in the transaction
#         for vin in tx['vin']:
#             # Append the txid to the list
#             txid_bytes = bytes.fromhex(vin["txid"])
#             reversed_txid = (txid_bytes[::-1]).hex()
#             txid_list.append(reversed_txid)  # Encode the strings to bytes
            
#     while len(txid_list) > 1:
#         next_level = []
#         for i in range(0, len(txid_list), 2):
#             pair_hash = b''
#             if i + 1 == len(txid_list):
#                 # In case of an odd number of elements, duplicate the last one
#                 pair_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i])).digest()).digest()
#             else:
#                 pair_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i + 1])).digest()).digest()
#             next_level.append(pair_hash.hex())
#         txid_list = next_level
        
#     return bytes.fromhex(txid_list[0])

def merkleroot(txids) -> bytes:
    # Initialize an empty list to store txids
    txid_list = []
    txids.insert(0, coinbase_txid)
    for txid in txids:
            # Append the txid to the list
                txid_bytes = bytes.fromhex(txid)
                reversed_txid = (txid_bytes[::-1]).hex()
                txid_list.append(reversed_txid)  # Encode the strings to bytes
            
    while len(txid_list) > 1:
        next_level = []
        for i in range(0, len(txid_list), 2):
            pair_hash = b''
            if i + 1 == len(txid_list):
                # In case of an odd number of elements, duplicate the last one
                pair_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i])).digest()).digest()
            else:
                pair_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i + 1])).digest()).digest()
            next_level.append(pair_hash.hex())
        txid_list = next_level
        
    return bytes.fromhex(txid_list[0])

def mine_block(block: Dict, difficulty_target: int, transactions: List[Dict]) -> Dict:
    nonce = 0
    max_nonce = 2**32  # Maximum value for a 32-bit number

    bits = difficulty_target.to_bytes(32, 'big')
    exponent = len(bits)
    significand = bits[:3]  # Get the first three bytes as the significand
    compact_target = (exponent << 24) | int.from_bytes(significand, 'big')
    mr = merkleroot(selected_txids) #should add coinbase tx but still works
    while nonce < max_nonce:
        block_header = block['header']
        block_header['nonce'] = nonce

        # Serialize the block header
        header_bytes = (
            block_header['version'].to_bytes(4, 'little') +
            bytes.fromhex(block_header['previous_block_hash']) +
            # createmerkleroot(transactions) +
            mr +
            block_header['time'].to_bytes(4, 'little') +
            b'\xff\xff\x00\x1f' +  # Use the compact representation
            block_header['nonce'].to_bytes(4, 'little')
        )
        global header_hex
        header_hex = header_bytes.hex()
        # Calculate hash of the serialized block
        block_hash = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
        reversed_block_hash = block_hash[::-1]
        # Check if hash meets difficulty target
        if int.from_bytes(reversed_block_hash, 'big') < difficulty_target:
            block['header']['hash'] = block_hash.hex()
            print(f"Block successfully mined with nonce: {nonce}, hash: {block['header']['hash']}")
            return block

        nonce += 1

    raise ValueError("Failed to mine block: exceeded max nonce without finding a valid hash")

def output_to_file(transactions: List[Dict]):
    with open('output.txt', 'w') as file:
        file.write(header_hex + "\n")
        # Write the coinbase transaction 
        file.write(coinbase_tx_hex + "\n")
        # Write the txids of all transactions (excluding the coinbase transaction)
        for tx in selected_txids:
                file.write(tx + "\n")

        # filepath = os.path.join(os.getcwd(), 'valid.json')
        # with open(filepath, 'r') as txids:
        #         transaction_data = json.load(txids)

        # for txid in txids:
        #     file.write(txid + '\n')

def main():
    transactions = read_transactions("mempool")
    block = construct_block(transactions, "123456789abcdefgh", 0)
    mine_block(block, DIFFICULTY_TARGET, transactions)
    output_to_file(transactions)

if __name__ == "__main__":
    main()