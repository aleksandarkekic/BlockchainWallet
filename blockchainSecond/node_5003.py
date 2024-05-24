import base64
import datetime
import hashlib
import config
import requests
import json
from uuid import uuid4
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from uuid import uuid4
from rsaKey import Encrypt

class Blockchain:
    def __init__(self):
        # Initialize a chain which will contain blocks
        self.chain = []  # a simple list containing blovks
        # Create a list which contains a list of transactions before they
        # are added to the block. Think of it as a cache of transactions which
        # happened, but are not yet written to a block in a blockchain.
        self.transactions = []
        # Create a genesis block - the first block
        # Previous hash is 0 because this is a genesis block!
        self.create_block(proof=1, previous_hash='0')
        # Create a set of nodes
        self.nodes = set()
        self.name_receiver_priv_key=""

    def create_block(self, proof, previous_hash):
        if len(self.transactions) != 0:
            print(self.transactions[0])
            signature = self.transactions[0].get('signature', None)
            if signature is not None:
                print(signature)
                Encrypt.verify_signature("public3.pem",self.transactions,base64.b64decode(signature), self.name_receiver_priv_key)
        value = f"{self.transactions}"
        self.transactions = value
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 # Here we can add any additional data related to the currency
                 'transactions': self.transactions
                 }
        # Now we need to empty the transactions list, since all those transactions
        # are now contained in the block.
        self.transactions = []
        # Append block to the blockchain
        self.chain.append(block)
        self.save_blockchain()
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1  # nonce value
        check_proof = False
        while check_proof is False:
            # Problem to be solved (this makes the minig hard)
            # operation has to be non-symetrical!!!
            hash_operation = hashlib.sha256(
                str(config.BLOCKCHAIN_PROBLEM_OPERATION_LAMBDA(previous_proof, new_proof)).encode()).hexdigest()
            # Check if first 4 characters are zeros
            if hash_operation[:len(config.LEADING_ZEROS)] == config.LEADING_ZEROS:
                check_proof = True
            else:
                new_proof += 1
        # Check proof is now true
        return new_proof

    def hash_of_block(self, block):
        # Convert a dictionary to string (JSON)
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            # 1 Check the previous hash
            block = chain[block_index]
            if block['previous_hash'] != self.hash_of_block(previous_block):
                return False
            # 2 Check all proofs of work
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(config.BLOCKCHAIN_PROBLEM_OPERATION_LAMBDA(previous_proof, proof)).encode()).hexdigest()
            if hash_operation[:len(config.LEADING_ZEROS)] != config.LEADING_ZEROS:
                return False
            # Update variables
            previous_block = block
            block_index += 1
        return True

    # this method adds a transaction,
    # and before that encrypts the data from the transaction with the receiver's public key and base64 encodes it
    # digital signing with the sender's private key is also done
    def add_transaction(self, transaction_info):
        sender=transaction_info['sender']
        receiver=transaction_info['receiver']
        sender_pub_key= self.return_right_public_key_file(sender)
        receiver_pub_key=self.return_right_public_key_file(receiver)
        if receiver_pub_key == "public2.pem":
            self.name_receiver_priv_key="private2.pem"
        elif receiver_pub_key == "public3.pem":
            self.name_receiver_priv_key = "private3.pem"
        else:
            self.name_receiver_priv_key = "private1.pem"
        transaction=transaction_info['sender']+transaction_info['receiver']+str(transaction_info['amount'])
        print(transaction+receiver_pub_key)
        hash=Encrypt.generisi_sha512_hash(transaction)

        self.transactions.append({'sender': base64.b64encode(Encrypt.encryption(transaction_info['sender'],receiver_pub_key)),
                                  'receiver': base64.b64encode(Encrypt.encryption(transaction_info['receiver'],receiver_pub_key)),
                                  'amount':  base64.b64encode(Encrypt.encryption(transaction_info['amount'],receiver_pub_key)),
                                  'signature': base64.b64encode(Encrypt.dgst('private3.pem',hash))
                                  })
        #value = f"{self.transactions}"
        #self.transactions = value
        print(type(self.transactions))
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        # Add to the list of nodes
        # parsed_url() method returns ParseResult object which has an attribute netloc
        # which is in a format adress:port eg. 127.0.0.1:5000
        self.nodes.add(parsed_url.netloc)

    # Replaces the current chain with the longest valid chain from the network
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            # Find the largest chain (send a request)
            response = requests.get(f'http://{node}/get-chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # Check chain if it is the longest one and also a valid one
                if length > max_length and requests.get(f'http://{node}/is-valid').json()["message"].__eq__("The Blockchain is valid!"):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            # Replace the chain
            self.chain = longest_chain
            self.save_blockchain()
            return True
        # Otherwise, the chain is not replaced
        return False

    # saveing blockchain into file
    def save_blockchain(self, filename='node_5003.json'):
        with open(filename, 'w') as file:
            json.dump({'chain': self.chain}, file, indent=2)

    #this function, based on the hash value, returns right public key
    def return_right_public_key_file(self,hash):
        try:
            with open('key_hash_pairs', 'r') as fajl:
                lines = fajl.readlines()
                for line in lines:
                    first_str, second_str = line.strip().split(',')
                    if second_str == hash:
                        return first_str
            print(f"Drugi string '{hash}' nije pronađen u datoteci key_hash_pairs.")
            return None
        except FileNotFoundError:
            print(f"Datoteka key_hash_pairs nije pronađena.")
            return None
        except Exception as e:
            print(f"Greška prilikom čitanja podataka: {str(e)}")
            return None


# ======================= FLASK APP ===========================================

# Create a Web App (Flask-based)
app = Flask(__name__)

# Creating an address for node on Port 5000
node_address = str(uuid4()).replace('-', '')

# Create a Blockchain
blockchain = Blockchain()


# Minig a block
@app.route('/mine-block', methods=['GET'])
def mine_block():
    # Get the previous proof
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    # Get previous hash
    previous_hash = blockchain.hash_of_block(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congratulations! You have just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']
                }
    return jsonify(response), 200


# Getting the full Blockchain
@app.route('/get-chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)
                }
    return jsonify(response), 200


# Checking if the blockchain is valid
@app.route('/is-valid', methods=['GET'])
def is_blockchain_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'The Blockchain is valid!'}
    else:
        response = {'message': 'The Blockchain is not valid!'}
    return jsonify(response), 200


# Adding a new transaction to the Blockchain
@app.route('/add-transaction', methods=['POST'])
def add_transaction():
    # Get the JSON file posted in Postman, or by calling this endpoint
    json = request.get_json()
    # Check all the keys in the received JSON
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'ERROR: Some elements of the transaction JSON are missing!', 400  # Bad Request code
    # Add transaction to the next block,
    index = blockchain.add_transaction(json)
    response = {'message': f'This transaction will be added to block {index}'}
    return jsonify(response), 201  # Created code


# Decentralize a Blockchain

# Connecting new nodes
@app.route('/connect-node', methods=['POST'])
def connect_node():
    json = request.get_json()
    # Connect a new node
    nodes = json.get('nodes')  # List of addresses
    # Make sure that the list is not empty
    if nodes is None:
        return "ERROR: No node", 400
    # Loop over the nodes and add them one by one
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected.',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201  # Created code


# Replacing the chain by the longest chain if needed
@app.route('/replace-chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The node had different chains, so the chain was replaced by the longest one!',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': ' All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200


# Running the app
app.run(host=config.HOST, port=5003)

























