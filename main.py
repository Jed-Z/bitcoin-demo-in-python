#!/usr/bin/env python
# coding: utf-8

# # A Simple Bitcoin Demo in Python

# Install requirements:
# ```bash
# pip install ecdsa
# pip install base58
# ```

# In[1]:


import random
import hashlib
import ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import base58


# ## 1. Merkle Tree

# In[2]:


def double_sha256(byts):
    '''Purpose SHA256 twice to the bytes.'''
    return hashlib.sha256(hashlib.sha256(byts).digest()).digest()


# In[3]:


class MerkleTree:
    def __init__(self):
        self.txid_list = list()
        self.merkle_root = bytes()

    def make_merkle_tree(self, txid_list, is_sorted=True):
        '''Compute merkle root for the given list of TXIDs.'''
        if len(txid_list) == 0:
            raise ValueError("empty list")

        # Sort TXIDs (strings) in lexicographical order if not ordered
        if is_sorted:
            self.txid_list = txid_list
        else:
            self.txid_list = sorted(txid_list)

        # Compute merkle root row by row
        hashes = [s for s in self.txid_list]
        while len(hashes) > 1:
            if len(hashes) & 1:  # Number of hashes is odd
                hashes.append(hashes[-1])
            next_hashes = []
            for i in range(0, len(hashes), 2):
                next_hashes.append(hashes[i] + hashes[i+1])
            hashes = [double_sha256(s) for s in next_hashes]  # Hashes are bytes, not texts

        self.merkle_root = hashes[0]
        return self.merkle_root  # 32 bytes


# ## 2 Bitcoin Accounts

# In[4]:


class Account:
    pubkey_type = b'\x04'  # The identification byte 0x04 denotes uncompressed coordinates of public key
    
    def __init__(self, prikey=b''):
        '''
        Create a Bitcoin account using the given private key.
        If private key not provided, generate a new one randomly.
        '''
        if prikey:
            self.private_key = prikey
            self.public_key = self.gen_pubkey_from_prikey(prikey)
        else:
            self.private_key, self.public_key = self.gen_keypair()
        
        self.public_key_hash = self.gen_public_key_hash(self.public_key)
        self.address = self.gen_address_from_pkh(self.public_key_hash)

    @staticmethod
    def gen_keypair():
        '''Generate a new pair of keys using SECP256k1 ECDSA.'''
        sk = SigningKey.generate(curve=SECP256k1) # Private key
        vk = sk.verifying_key                     # Public key (without prefix)
        return sk.to_string(), Account.pubkey_type + vk.to_string()
        
    @staticmethod
    def gen_pubkey_from_prikey(prikey):
        '''Compute public key from the given private key.'''
        sk = SigningKey.from_string(prikey, curve=SECP256k1)
        vk = sk.verifying_key
        return Account.pubkey_type + vk.to_string()

    @staticmethod
    def gen_public_key_hash(pubkey):
        '''Compute public key hash with "double hash".'''
        # Note that pubkey is already prefixed
        temp = hashlib.sha256(pubkey).digest()
        h = hashlib.new('ripemd160')
        h.update(temp)
        return h.digest()

    @staticmethod
    def gen_address_from_pkh(pubkeyhash):
        '''Compute base58check encoded address.'''
        # Base58check encode
        version_prefix = b'\x00'  # Version prefix of Bitcoin addresses is 0x00
        return base58.b58encode_check(version_prefix + pubkeyhash)


# In[5]:


# Example from textbook
example_account = Account(bytes.fromhex("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD"))
print("Public key:", example_account.public_key.hex())
print("Address", example_account.address)


# In[6]:


# Generate 100 Bitcoin accounts for testing
test_accounts = [Account() for i in range(100)]


# ## 3. Signature and Verification

# In[7]:


test_message = b"blockchain-ss-2021"
print(test_message.hex())


# In[8]:


def sign(message, prikey):
    '''
    Sign a byte message using the private key.
    The signature is encoded in DER format.
    '''
    sk = SigningKey.from_string(prikey, curve=SECP256k1)
    return sk.sign(message, sigencode=ecdsa.util.sigencode_der)  # DER format
    
def verify(signature, message, pubkey):
    '''
    Verify signature using the public key.
    Returns true if succeed. Otherwise raises errors.
    '''
    vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
    return vk.verify(signature, message, sigdecode=ecdsa.util.sigdecode_der)


# In[9]:


fail_flag = False

for account in test_accounts:
    # Sign the message
    test_signature = sign(test_message, account.private_key)
    
    # Verify the signature
    try:
        verify(test_signature, test_message, account.public_key[1:])
    except ecdsa.BadSignatureError as e:
        print(e)
        fail_flag = True
        
if not fail_flag:
    print("All succeeded.")


# In[10]:


# A bad case
test_signature = sign(test_message, test_accounts[0].private_key)
temp = list(test_signature)
temp[-1] = (temp[-1] + 1) % 256  # Modifying one byte in the signature causes corruption
bad_signature = bytes(temp)

print("Correct signature:", test_signature.hex())
print("Corrupt signature:", bad_signature.hex())

try:
    verify(bad_signature, test_message, test_accounts[0].public_key)  # Will raise an error
except ecdsa.BadSignatureError as e:
    print("BadSignatureError:", e)


# ## 4. Bitcoin Transactions

# In[11]:


def int_to_varint(value):
    if value <= 0xfc:
        return value.to_bytes(1, 'little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')


# In[12]:


class ScriptPubKey:
    def __init__(self, pubkeyhash):
        self.public_key_hash = pubkeyhash
        self.before = b'\x76\xa9\x14' # OP_DUP OP_HASH160
        self.after = b'\x88\xac'      # OP_EQUALVERIFY OP_CHECKSIG
    
    def encode(self):
        return self.before + self.public_key_hash + self.after
    
class ScriptSig:
    def __init__(self, sig, pubkey):
        self.signature = sig
        self.public_key = pubkey
        self.sighash = b'\x01'  # SIGHASH_ALL
    
    def encode(self):
        raw = bytes()
        raw += int_to_varint(len(self.signature) + 1)
        raw += self.signature
        raw += self.sighash
        raw += int_to_varint(len(self.public_key))
        raw += self.public_key
        return raw


# In[13]:


class Transaction:
    def __init__(self):
        self.version = 1
        self.vin = list()  # List of class Transaction.Input
        self.vout = list() # List of class Transaction.Output
        self.locktime = 0
    
    def encode(self):
        '''Serialize transaction data into bytes.'''
        tx_raw = bytes()
        tx_raw += self.version.to_bytes(4, 'little')  # 4 bytes
        tx_raw += int_to_varint(len(self.vin))        # VarInt
        for v in self.vin:
            tx_raw += v.encode()
        tx_raw += int_to_varint(len(self.vout))       # VarInt
        for v in self.vout:
            tx_raw += v.encode()
        tx_raw += self.locktime.to_bytes(4, 'little') # 4 bytes
        return tx_raw

    def add_input(self, txid, vout, sig, pubkey):
        v = self.Input(txid, vout, sig, pubkey)
        self.vin.append(v)
        
    def add_output(self, value, pubkeyhash):
        v = self.Output(value, pubkeyhash)
        self.vout.append(v)
        
    def get_txid(self):
        return double_sha256(self.encode())
    
    # --- Below are inner classes ---
            
    class Output:
        def __init__(self, value, pubkeyhash):
            self.value = value  # 8 bytes, in satoshis
            self.script_pubkey = ScriptPubKey(pubkeyhash)
            
        def encode(self):
            locking_script = self.script_pubkey.encode()
            
            out_raw = bytes()
            out_raw += self.value.to_bytes(8, 'little')
            out_raw += int_to_varint(len(locking_script))  # Locking script size in bytes
            out_raw += locking_script
            return out_raw

    class Input:
        def __init__(self, txid, vout, sig, pubkey):
            assert len(txid) == 32
            self.txid = txid
            self.vout = vout  # index of output of TXID
            self.script_sig = ScriptSig(sig, pubkey)
            self.sequence = 0xFFFFFFFF
            
        def encode(self):
            unlocking_script = self.script_sig.encode()
            
            in_raw = bytes()
            in_raw += self.txid[::-1]                      # 32 bytes, reversed byte order
            in_raw += self.vout.to_bytes(4, 'little')      # 4 bytes
            in_raw += int_to_varint(len(unlocking_script)) # VarInt, unlocking script size
            in_raw += unlocking_script
            in_raw += self.sequence.to_bytes(4, 'little')  # 4 bytes
            return in_raw


# In[14]:


# Example from textbook
tx = Transaction()
txid = bytes.fromhex("7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18")
sig = bytes.fromhex("3045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813")
pubkey = bytes.fromhex("0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf")
tx.add_input(txid, 0, sig, pubkey)
tx.add_output(1500000, bytes.fromhex("ab68025513c3dbd2f7b92a94e0581f5d50f654e7"))
tx.add_output(8450000, bytes.fromhex("7f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a8"))
tx.encode().hex()


# In[15]:


# Generate 1000 transactions for testing
test_transactions = []

for i in range(1000):
    tx = Transaction()
    tx.version = 1
    tx.locktime = 1
    
    num_in = random.randint(1, 3)
    for i in range(num_in):
        account = random.choice(test_accounts)
        txid = random.randint(0, 2**256).to_bytes(32, 'little')
        vout = random.randint(0, 2)
        rand_msg = b'12312313'
        sig = sign(rand_msg, account.private_key)
        pubkey = account.public_key
        
        tx.add_input(txid, vout, sig, pubkey)
    
    num_out = random.randint(1, 3)
    for i in range(num_out):
        account = random.choice(test_accounts)
        value = random.randint(100000, 10000000)
        pubkeyhash = account.public_key_hash
        
        tx.add_output(value, pubkeyhash)
    
    test_transactions.append(tx)


# ## 5. Bitcoin Blocks

# In[16]:


class Block:
    def __init__(self, prev_hash=int(0).to_bytes(32, 'little')):
        assert len(prev_hash) == 32
        self.block_header = self.Header(prev_hash)
        self.transactions = list()  # List of class Transaction
        
    def encode(self):
        raw = bytes()
        raw += self.block_header.encode()
        raw += int_to_varint(len(self.transactions))
        for tx in self.transactions:
            raw += tx.encode()
            
        block_size = len(raw)
        raw = int_to_varint(block_size) + raw
        return raw
        
    def add_transaction(self, tx):
        self.transactions.append(tx)
        
    def gen_merkle_root(self):
        txid_list = []
        for tx in self.transactions:
            txid_list.append(tx.get_txid())
            
        mt = MerkleTree()
        self.block_header.merkle_root = mt.make_merkle_tree(txid_list)
        
    def get_hash(self):
        return double_sha256(self.encode())

    # --- Below are inner classes ---
    
    class Header:
        def __init__(self, prev):
            self.version = int()
            self.previous_block_hash = prev
            self.merkle_root = bytes()
            self.timestamp = int()
            self.difficulty_target = int()
            self.nonce = int()
            
        def encode(self):
            raw = bytes()
            raw += self.version.to_bytes(4, 'little')
            raw += self.previous_block_hash
            raw += self.merkle_root
            raw += self.timestamp.to_bytes(4, 'little')
            raw += self.difficulty_target.to_bytes(4, 'little')
            raw += self.nonce.to_bytes(4, 'little')
            return raw


# In[17]:


# Generate 10 blocks for testing
test_blocks = []

for i in range(10):
    if i == 0:
        block = Block()  # prev_hash of the first block is all-zero
    else:
        block = Block(test_blocks[i-1].get_hash())  # Construct a chain of block hashes
    txs = test_transactions[i*10:(i+1)*10]
    for tx in txs:
        block.add_transaction(tx)
    block.gen_merkle_root()
    test_blocks.append(block)


# In[18]:


test_blocks[0].encode().hex()


# In[ ]:




