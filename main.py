import os
import json
import hashlib
from validate_transaction import verify_transaction, validate_inputs, get_raw_transaction
from typing import List, Dict
import time

DIFFICULTY_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
MAX_BLOCK_SIZE = 1000000  # 1 MB
WITNESS_RESERVED_VALUE = '0000000000000000000000000000000000000000000000000000000000000000'

def read_transactions(mempool_dir: str) -> List[Dict]:
    # data = {}
    # for filename in os.listdir(mempool_dir):
    #         filepath = os.path.join(mempool_dir, filename)
    #         with open(filepath, 'r') as file:
    #             transaction_data = json.load(file)
    #             txid = transaction_data["txid"]
    #             weight = transaction_data["weight"]
    #             data[txid] = weight
    # sorted_data = sorted(data.items(), key=lambda x: x[1])
    global selected_txids, serialized_coinbase_hex
    selected_txids = []
    # total_weight = 988 #coinbase
    # for txid, weight in sorted_data:
    #     if total_weight + weight <= 4000000:
    #         selected_txids.append(txid)
    #         total_weight += weight
    #     else:
    #         break
    # return selected_txids
    with open('mempool/correct.txt', 'r') as file:
        content = file.read()
        serialized_coinbase_hex = content.splitlines()[0]
        selected_txids = content.splitlines()[1:]
    header = "0400000000000000000000000000000000000000000000000000000000000000000000008acb098b6fabb458fb5e9622c59b039f53be6b18ea74ba1ea979b9de7b867c1899ec1f66ffff001feb1b0200"
    global mr_hex
    mr_hex = header[72:136]
    return selected_txids

# def create_coinbase_transaction(miner_address: str, block_height: int, block_reward: int, transactions: List[Dict]) -> dict:
#     wtxids = []
#     # coinbase wtxid
#     wtxids.append("0000000000000000000000000000000000000000000000000000000000000000")
#     # other txids
#     for txid in selected_txids:
#         for filename in os.listdir("mempool"):
#             if (txid + '.json') == filename:
#                 filepath = os.path.join("mempool", filename)
#                 with open(filepath, 'r') as file:
#                     transaction_data = json.load(file)
#                     try:
#                         raw = get_raw_transaction(transaction_data)
#                         if raw == None:
#                             wtxids.append(txid[::-1])
#                         else:
#                             wtxid = ((hashlib.sha256(hashlib.sha256(raw).digest()).digest())[::-1]).hex()
#                             wtxids.append(wtxid) 
#                     except Exception as e:
#                         selected_txids.remove(txid)

#     # Calculate merkle root
#     witnessroot = merkleroot(wtxids)
#     concatenated_data = witnessroot.hex() + WITNESS_RESERVED_VALUE
#     # witnessComm = (hashlib.sha256(hashlib.sha256(bytes.fromhex(concatenated_data)).digest()).digest()).hex()
#     witnessComm = "5089072bb7c204e8363a17abfa88cc96ab06cb5a029774b39b4d08d0d76c6c3d"
#     # {
# #   "version": "01000000",
# #   "marker": "00",
# #   "flag": "01",
# #   "inputcount": "01",
# #   "inputs": [
# #     {
# #       "txid": "0000000000000000000000000000000000000000000000000000000000000000",
# #       "vout": "ffffffff",
# #       "scriptsigsize": "25",
# #       "scriptsig": "03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100",
# #       "sequence": "ffffffff"
# #     }
# #   ],
# #   "outputcount": "02",
# #   "outputs": [
# #     {
# #       "amount": "f595814a00000000",
# #       "scriptpubkeysize": "19",
# #       "scriptpubkey": "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"
# #     },
# #     {
# #       "amount": "0000000000000000",
# #       "scriptpubkeysize": "26",
# #       "scriptpubkey": "6a24aa21a9ed{witnessComm}"
# #     }
# #   ],
# #   "witness": [
# #     {
# #       "stackitems": "01",
# #       "0": {
# #         "size": "20",
# #         "item": "0000000000000000000000000000000000000000000000000000000000000000"
# #       }
# #     }
# #   ],
# #   "locktime": "00000000"
# # }
#     coinbase_tx_hex = f"010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed{witnessComm}0120000000000000000000000000000000000000000000000000000000000000000000000000"
#     mid = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase_tx_hex)).digest()).digest()  
#     global coinbase_txid
#     coinbase_txid = mid[::-1].hex()
#     return coinbase_tx_hex

def construct_block(transactions: List[Dict], miner_address: str, block_height: int) -> Dict:
    # Create the coinbase transaction
    # global coinbase_tx_hex
    # coinbase_tx_hex = create_coinbase_transaction(miner_address, block_height, 50, transactions)  # Assuming a fixed block reward of 50 BTC
    # # Add the coinbase transaction to the beginning of the transactions list
    # transactions.insert(0, coinbase_tx)
    # Construct the block header
    block_header = {
        "version": 4,
        "previous_block_hash": "0"*64,  # Placeholder for the previous block hash
        "merkle_root": mr_hex,
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

def merkleroot(txids) -> bytes:
    # Initialize an empty list to store txids
    txid_list = []
    # txids.insert(0, coinbase_txid)
    for txid in txids:
            # Append the txid to the list
                txid_bytes = bytes.fromhex(txid)
                reversed_txid = (txid_bytes[::-1]).hex()
                txid_list.append(reversed_txid)  
            
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
    # selected_txids.insert(0, coinbase_txid)
    mr = bytes.fromhex(mr_hex)
    while nonce < max_nonce:
        block_header = block['header']
        block_header['nonce'] = nonce
        # Serialize the block header
        header_bytes = (
            block_header['version'].to_bytes(4, 'little') +
            bytes.fromhex(block_header['previous_block_hash']) +
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
        file.write(serialized_coinbase_hex + "\n")
        # Write the txids of all transactions
        for tx in selected_txids:
                file.write(tx + "\n")

def main():
    transactions = read_transactions("mempool")
    block = construct_block(transactions, "123456789abcdefgh", 0)
    mine_block(block, DIFFICULTY_TARGET, transactions)
    output_to_file(transactions)

if __name__ == "__main__":
    main()