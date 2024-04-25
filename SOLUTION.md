# Summer of Bitcoin 2024: Mine your first block

The challenge is to create a script simulating the mining process of block from the given set of transactions.

The script does the following :
    1. Load and parse JSON files from the mempool directory to extract transaction data.
    2. Implement validation logic to filter out invalid transactions.
    3. Construct a block by organizing valid transactions into a block structure, including a coinbase transaction for the block reward.
    4. Implement a proof-of-work algorithm to find a block hash that meets the difficulty target.
    5. Generate an output.txt file with the block header, serialized coinbase transaction, and transaction IDs.

The psuedo code to understand this is :

```
function readTransactions(directory):
    transactions = []
    for each file in directory:
        transaction = parseJSON(file)
        transactions.append(transaction)
    return transactions

function validateTransactions(transactions):
    validTransactions = []
    for transaction in transactions:
        if isValid(transaction):
            validTransactions.append(transaction)
    return validTransactions

function constructBlock(validTransactions):
    block = new Block()
    block.addCoinbaseTransaction()
    for transaction in validTransactions:
        block.addTransaction(transaction)
    return block

function mineBlock(block, difficultyTarget):
    nonce = 0
    while true:
        blockHeader = constructBlockHeader(block, nonce)
        blockHash = hash(blockHeader)
        if blockHash < difficultyTarget:
            return blockHeader, blockHash
        nonce += 1

function main():
    transactions = readTransactions("mempool")
    validTransactions = validateTransactions(transactions)
    block = constructBlock(validTransactions)
    blockHeader, blockHash = mineBlock(block, DIFFICULTY_TARGET)
    outputToFile(blockHeader, block.transactions)

main()
```

Some stuff to know :
    a. Block Header - Contains metadata about the block, including the previous block hash, timestamp, and nonce.
    b. Coinbase Transaction: A special transaction included in each block that awards the miner the block reward.
    c. Difficulty Target: A value that the block hash must be less than for the block to be considered valid.
    d. Proof of Work: A computational effort required to mine a block, involving incrementing a nonce until the block hash meets the difficulty target.
    e. A bitcoin transaction is just a bunch of bytes. And if you decode them, you'll find that they're just unlocking batches of bitcoins and locking them up in to new batches.
    f. TXID is is created by double-SHA256ing of the following fields in the raw transaction data. TXID = HASH256([version][inputs][outputs][locktime]). The TXIDs of transactions are also hashed together to create a merkle root for the block header. This basically creates a "fingerprint" for the transactions that have been included in the block, so if any of the transaction change, so will the fingerprint.
    g. A transaction fee is the remainder of a transaction.
    h. Mempool is  just a pool of unconfirmed transactions.
    i. A candidate block is a block of transactions a miner attempts to add to the blockchain. During the mining process, each miner will collect transactions from their memory pool in to a candidate block. They will then repeatedly hash this block to try and get a block hash below the target. If a miner can get a block hash below the target, their candidate block can be added on to the blockchain. They will then broadcast this "mined" candidate block to the other nodes on the network, where each node will verify and add it to their blockchain too.
    j. The block header is a small amount of metadata the summarizes all the data inside the block. This is what a miner will be hashing as they attempt to mine the candidate block.
    k. The target is a number that a block hash for a candidate block must get below before the block can be added on to the blockchain.
    l. The nonce is a spare field at the end of the block header used for mining. Miners increment the nonce value when mining so that they can get completely different hash results for the block header of their candidate block. They hope to stumble upon a "magic" nonce value that will produce a block hash that is below the current target. There is no guarantee that there will be a "magic" nonce value for any given block header. In fact, it's likely that there will be no nonce value that will produce a hash result below the target.

Precomputing all stuff to save memory! 

Lets dive deep into the problems step by step :
    1. Iterate over each file in the mempool directory, parsing the JSON content to extract metadata and store them in data structure. 
    2. Based on criteria such as size, format, signatures, descendants, conflicting nature, only spend coins that already exist and more on the basis of metadata. Verify transaction signatures using public key cryptography. This step requires understanding of digital signatures and the specific algorithm used (e.g., ECDSA for Bitcoin). Verify the signature (scriptsig or witness) against the corresponding public key and the transaction data. Check that the transaction inputs are valid UTXOs and not double spends. If a miner mines a block containing invalid transactions and broadcasts it to the network, all of the nodes will reject it, and all of their effort for mining the block will be wasted. The parent(s) of a transaction must always come before the child transaction. Implement a topological sorting algorithm to determine a valid transaction ordering. For example, if a transaction has ancestors that are currently in the mempool, those ancestors must be included above it in the candidate block.the transactions you include in your candidate block (including the size of the block header and transaction count) must be within this size limit. You can only include a transaction in a block if you also include all of its parents first. Therefore, if a memory pool transaction has ancestors, a miner will calculate the ancestor fee rate to work out whether it's worth including that transaction compared to another transaction that doesn't have any ancestors. Each node validates the transactions in a block from top to bottom, so if you include a parent after a child, it will appear as though that child transaction is spending outputs that do not already exist (and would therefore be invalid).
    Then pick each valid transaction, and locally run serialization step to get fee and weight and marked it as correct to save CI time and prevent memory issue. Mempool edited to only include valid txns with fee and weight.
    3. Ensure the coinbase transaction is the first transaction in the block. If miner dont accept the block reward, those bitcoins should be wasted. Define a block structure that includes the block header and the list of transactions. Calculate the Merkle root of the transactions and include it in the block header. Calculate witness commitment for the serialized coinbase transaction by concatinating Witness Reserved Value and Witness Root obtained by double hashing serialized data.
    4. Implement a loop that increments the nonce in the block header and calculates the block's hash until it finds a hash that meets the difficulty target. Use a cryptographic hash function, such as SHA-256, for hashing the block header.
    5. After mining the block, serialize the block data and write it to output.txt.
    
Fee Optimization :
To maximize the miner's profit, transactions can be selected based on their fees. This requires calculating the fee for each transaction (the difference between inputs and outputs) and prioritizing transactions with higher fees. Also consider the size of each transaction to ensure the block does not exceed the maximum block size. Sort the valid transactions in the mempool based on their fee in descending order. This ensures that transactions with higher fees are considered first. While selecting transactions, keep track of the total block size to ensure it doesn't exceed the maximum block size limit. Include transactions until the block is nearly full. Use algorithms such as the knapsack problem to select a subset of transactions that maximize total fees while fitting within the block size limit. This involves considering both the fee and size of each transaction to find the optimal combination.

References :
http://royalforkblog.github.io/2014/11/20/txn-demo/
https://learnmeabitcoin.com/technical/
https://en.bitcoin.it/wiki/BIP_0143
https://en.bitcoin.it/wiki/BIP_0141