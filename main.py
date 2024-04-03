import os
import json
import hashlib
from validate_transaction import verify_transaction, validate_inputs
from typing import List, Dict
import time

DIFFICULTY_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
MAX_BLOCK_SIZE = 1000000  # 1 MB

valid_transactions = []

def read_transactions(mempool_dir: str) -> List[Dict]:
    for filename in os.listdir(mempool_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(mempool_dir, filename)
            with open(filepath, 'r') as file:
                transaction_data = json.load(file)
                if verify_transaction(transaction_data, filename):
                    valid_transactions.append(transaction_data)
    return select_transactions_based_on_fees(valid_transactions, MAX_BLOCK_SIZE)

def calculate_transaction_size(transaction: Dict) -> int:
    # Implement transaction size calculation based on transaction data
    return len(json.dumps(transaction))

def select_transactions_based_on_fees(transactions, max_block_size):
    # Sort transactions by fee in descending order
    transactions.sort(key=lambda txn: validate_inputs(txn['vin'], txn['vout']), reverse=True)
    selected_transactions = []
    current_block_size = 0
    for tx in transactions:
        tx_size = calculate_transaction_size(tx)
        if current_block_size + tx_size <= max_block_size:
            selected_transactions.append(tx)
            current_block_size += tx_size
        else:
            break
    return selected_transactions

def create_coinbase_transaction(miner_address: str, block_height: int, block_reward: int) -> dict:
    """
    Create a coinbase transaction.

    :param miner_address: The address of the miner to receive the block reward.
    :param block_height: The height of the block being mined.
    :param block_reward: The total block reward (block subsidy + transaction fees).
    :return: A dictionary representing the coinbase transaction.
    """
    # The coinbase transaction's input is always a single input with specific values
    vin = {
        'txid': '0000000000000000000000000000000000000000000000000000000000000000',
        'vout': 0xffffffff,
        'scriptSig': {
            'asm': f'{block_height}',  # Using block height as per BIP 34
            'hex': block_height.to_bytes(4, 'little').hex()  # Convert block height to little-endian hex
        },
        'sequence': 0xffffffff
    }

    # The output of the coinbase transaction sends the block reward to the miner's address
    vout = {
        'value': block_reward,
        'scriptPubKey': {
            'asm': f'OP_DUP OP_HASH160 {miner_address} OP_EQUALVERIFY OP_CHECKSIG',
            'hex': ''  # The hex representation of the scriptPubKey would depend on the actual address format
        }
    }

    # The coinbase transaction itself
    coinbase_tx = {
        'version': 1,
        'inputs': [vin],
        'outputs': [vout],
        'locktime': 0
    }

    return coinbase_tx

def construct_block(transactions: List[Dict], miner_address: str, block_height: int) -> Dict:
    # Create the coinbase transaction
    coinbase_tx = create_coinbase_transaction(miner_address, block_height, 50)  # Assuming a fixed block reward of 50 BTC

    # Add the coinbase transaction to the beginning of the transactions list
    transactions.insert(0, coinbase_tx)

    # Construct the block header
    block_header = {
        "version": 1,
        "previous_block_hash": "0" * 64,  # Placeholder for the previous block hash
        # No Merkle root included
        "time": int(time.time()),  # Placeholder for the block's timestamp
        "bits": 0x1d00ffff,  # Placeholder for the difficulty target
        "nonce": 0  # Placeholder for the nonce
    }

    # Assemble the block
    block = {
        "header": block_header,
        "transactions": transactions
    }

    return block

def mine_block(block: Dict, difficulty_target: int) -> Dict:
    nonce = 0
    while True:
        block['header']['nonce'] = nonce
        block_string = json.dumps(block, sort_keys=True)
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if int(block_hash, 16) < difficulty_target:
            block['header']['hash'] = block_hash
            return block
        nonce += 1

def output_to_file(block_header: Dict, transactions: List[Dict]):
    with open('output.txt', 'w') as file:
        # Write the block header
        file.write(json.dumps(block_header) + "\n")
        # Write the coinbase transaction 
        file.write(json.dumps(transactions[0]) + "\n")
        # Write the txids of all transactions (excluding the coinbase transaction)
        for tx in transactions[1:]:
            for vin in tx['vin']:
                file.write(vin["txid"] + "\n")


def main():
    transactions = read_transactions("mempool")
    block = construct_block(transactions, "123456789abcdefgh", 0)
    mined_block = mine_block(block, DIFFICULTY_TARGET)
    output_to_file(mined_block['header'], transactions)

if __name__ == "__main__":
    main()