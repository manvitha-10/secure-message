#!/usr/bin/env python3
"""
ITIS 6200/8200 - Secure Messaging Project (FILE-BASED VERSION)
Bob's Terminal Program
"""

import hashlib
import hmac as hmac_lib
import secrets
import time
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ============================================================================
# TASK 1: DIGITAL SIGNATURE
# ============================================================================

class DigitalSignature:
    """Digital signature mechanism using RSA"""
    
    @staticmethod
    def generate_keys():
        """Generate RSA key pair (public and private keys)"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def sign(message, private_key):
        """Sign a message with private key"""
        if isinstance(message, str):
            message = message.encode()
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify(message, signature, public_key):
        """Verify a signature with public key. Returns 1 if valid, 0 if invalid"""
        try:
            if isinstance(message, str):
                message = message.encode()
            
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return 1
        except:
            return 0

# ============================================================================
# TASK 2: DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================================

class DiffieHellman:
    """Diffie-Hellman key exchange implementation"""
    
    def __init__(self):
        self.p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                     "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                     "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                     "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                     "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                     "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                     "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                     "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                     "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                     "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                     "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
        self.g = 2
        self.private_key = None
        self.public_value = None
        self.shared_secret = None
    
    def generate_private_key(self):
        """Generate a random private key"""
        self.private_key = secrets.randbelow(self.p - 2) + 1
        return self.private_key
    
    def compute_public_value(self):
        """Compute g^b mod p"""
        if self.private_key is None:
            self.generate_private_key()
        self.public_value = pow(self.g, self.private_key, self.p)
        return self.public_value
    
    def compute_shared_secret(self, other_public_value):
        """Compute g^ab mod p using received public value"""
        self.shared_secret = pow(other_public_value, self.private_key, self.p)
        return self.shared_secret

# ============================================================================
# TASK 3: KEY DERIVATION FUNCTION (KDF)
# ============================================================================

class KeyDerivation:
    """Key Derivation Function using iterated hashing"""
    
    @staticmethod
    def derive_key(shared_secret, iterations=10000):
        """Derive encryption key from shared secret"""
        if isinstance(shared_secret, int):
            byte_length = (shared_secret.bit_length() + 7) // 8
            shared_secret = shared_secret.to_bytes(byte_length, byteorder='big')
        elif isinstance(shared_secret, str):
            shared_secret = shared_secret.encode()
        
        key = shared_secret
        for i in range(iterations):
            key = hashlib.sha256(key).digest()
        
        return key

# ============================================================================
# TASK 4: PSEUDO-RANDOM NUMBER GENERATOR (PRNG)
# ============================================================================

class PRNG:
    """Pseudo-Random Number Generator"""
    
    def __init__(self, seed_value=None):
        self.state = None
        if seed_value is not None:
            self.seed(seed_value)
        else:
            self.seed(int(time.time() * 1000000))
    
    def seed(self, seed_value):
        """Initialize the internal state with a seed value"""
        if isinstance(seed_value, str):
            seed_value = int(hashlib.sha256(seed_value.encode()).hexdigest(), 16)
        self.state = seed_value % (2**256)
    
    def reseed(self, additional_entropy):
        """Add more randomness to the current state"""
        if isinstance(additional_entropy, str):
            additional_entropy = int(hashlib.sha256(additional_entropy.encode()).hexdigest(), 16)
        self.state = (self.state + additional_entropy) % (2**256)
    
    def generate(self, num_bytes=16):
        """Generate random bytes"""
        self.state = int(hashlib.sha256(str(self.state).encode()).hexdigest(), 16)
        byte_length = min(num_bytes, 32)
        return self.state.to_bytes(32, byteorder='big')[:byte_length]

# ============================================================================
# TASK 5: SECURE MESSAGE EXCHANGE
# ============================================================================

class SecureMessaging:
    """Authenticated Encryption for secure message exchange"""
    
    def __init__(self, encryption_key, prng):
        self.encryption_key = encryption_key
        self.prng = prng
    
    def sym_dec(self, ciphertext, iv):
        """Symmetric decryption using AES-256 in CBC mode"""
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        padding_length = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_length]
        
        return plaintext
    
    def compute_hmac(self, data):
        """Compute HMAC-SHA256"""
        h = hmac_lib.new(self.encryption_key, data, hashlib.sha256)
        return h.digest()

# ============================================================================
# MAIN BOB PROGRAM
# ============================================================================

def print_header(text):
    """Print a nice header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def main():
    print("\n🔐 BOB'S TERMINAL - Secure Messaging Project")
    print(f"⏰ Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # TASK 1
    print_header("TASK 1: DIGITAL SIGNATURE")
    ds = DigitalSignature()
    bob_private_key, bob_public_key = ds.generate_keys()
    print("✓ Bob's RSA key pair generated")
    
    bob_public_pem = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("\n📋 Bob's Public Key:")
    print(bob_public_pem.decode())
    
    test_message = "Hello, this is Bob!"
    print(f"\n🧪 Testing signature with message: '{test_message}'")
    signature = ds.sign(test_message, bob_private_key)
    print(f"✓ Signature created (length: {len(signature)} bytes)")
    result = ds.verify(test_message, signature, bob_public_key)
    print(f"✓ Verification with Bob's public key: {result} (should be 1)")
    
    # TASK 2
    print_header("TASK 2: DIFFIE-HELLMAN KEY EXCHANGE")
    dh_bob = DiffieHellman()
    print(f"\n📋 Public parameters:")
    print(f"p (first 50 digits): {str(dh_bob.p)[:50]}...")
    print(f"g (generator): {dh_bob.g}")
    
    bob_private = dh_bob.generate_private_key()
    bob_public = dh_bob.compute_public_value()
    
    print(f"\n🔑 Bob's private key (first 20 digits): {str(bob_private)[:20]}...")
    print(f"📤 Bob's public value (first 50 digits): {str(bob_public)[:50]}...")
    
    bob_dh_signature = ds.sign(str(bob_public), bob_private_key)
    print(f"\n✓ Bob signs his public value")
    
    print("\n⏸️  Waiting for Alice to create alice_to_bob.json...")
    print("Press Enter when Alice has created the file:")
    input()
    
    # Read Alice's file
    try:
        with open('alice_to_bob.json', 'r') as f:
            alice_package = json.load(f)
        print("✅ Loaded Alice's data from alice_to_bob.json")
    except FileNotFoundError:
        print("❌ File alice_to_bob.json not found!")
        print("Make sure Alice has run her program and created the file.")
        return
    
    alice_public = int(alice_package['public_value'])
    alice_dh_signature = base64.b64decode(alice_package['signature'])
    alice_public_key_pem = alice_package['public_key'].encode()
    alice_public_key = serialization.load_pem_public_key(alice_public_key_pem, backend=default_backend())
    
    verification_result = ds.verify(str(alice_public), alice_dh_signature, alice_public_key)
    print(f"\n✓ Bob verifies Alice's signature: {verification_result} (should be 1)")
    
    # Save Bob's data for Alice
    bob_package = {
        'public_value': str(bob_public),
        'signature': base64.b64encode(bob_dh_signature).decode(),
        'public_key': bob_public_pem.decode()
    }
    
    with open('bob_to_alice.json', 'w') as f:
        json.dump(bob_package, f)
    
    print("\n" + "─"*70)
    print("✅ Bob's data saved to: bob_to_alice.json")
    print("📨 Alice can now read this file!")
    print("─"*70)
    
    if verification_result == 1:
        shared_secret = dh_bob.compute_shared_secret(alice_public)
        print(f"\n🔐 Shared secret computed (first 50 digits): {str(shared_secret)[:50]}...")
    else:
        print("❌ Signature verification failed!")
        return
    
    # TASK 3
    print_header("TASK 3: KEY DERIVATION FUNCTION")
    iterations = 10000
    encryption_key = KeyDerivation.derive_key(shared_secret, iterations)
    print(f"✓ Derived encryption key using {iterations} iterations of SHA-256")
    print(f"🔑 Encryption key (hex): {encryption_key.hex()}")
    
    # TASK 4
    print_header("TASK 4: PSEUDO-RANDOM NUMBER GENERATOR")
    prng = PRNG()
    print("✓ PRNG initialized")
    print("\n📊 Random sequence (5 numbers):")
    for i in range(5):
        rand_bytes = prng.generate(8)
        rand_int = int.from_bytes(rand_bytes, byteorder='big')
        print(f"  {i+1}. {rand_int}")
    
    # Deterministic test
    print("\n🧪 Deterministic test - Two sequences with same seed:")
    prng1 = PRNG(12345)
    prng2 = PRNG(12345)
    
    print("Sequence 1:")
    seq1 = []
    for i in range(5):
        rand_bytes = prng1.generate(8)
        num = int.from_bytes(rand_bytes, byteorder='big')
        seq1.append(num)
        print(f"  {i+1}. {num}")
    
    print("Sequence 2:")
    seq2 = []
    for i in range(5):
        rand_bytes = prng2.generate(8)
        num = int.from_bytes(rand_bytes, byteorder='big')
        seq2.append(num)
        print(f"  {i+1}. {num}")
    
    print(f"\n✓ Sequences identical: {seq1 == seq2}")
    
    # Different seed test
    print("\n🧪 Different seed test:")
    prng3 = PRNG(11111)
    prng4 = PRNG(99999)
    
    print("Seed 11111:")
    seq3 = []
    for i in range(3):
        rand_bytes = prng3.generate(8)
        num = int.from_bytes(rand_bytes, byteorder='big')
        seq3.append(num)
        print(f"  {i+1}. {num}")
    
    print("Seed 99999:")
    seq4 = []
    for i in range(3):
        rand_bytes = prng4.generate(8)
        num = int.from_bytes(rand_bytes, byteorder='big')
        seq4.append(num)
        print(f"  {i+1}. {num}")
    
    print(f"\n✓ Sequences different: {seq3 != seq4}")
    
    # TASK 5
    print_header("TASK 5: RECEIVE MESSAGE FROM ALICE")
    msg_prng = PRNG(int(time.time() * 1000000))
    secure_msg = SecureMessaging(encryption_key, msg_prng)
    
    print("\n⏸️  Waiting for Alice to create alice_message_to_bob.json...")
    print("Press Enter when Alice has sent the message:")
    input()
    
    try:
        with open('alice_message_to_bob.json', 'r') as f:
            message_package = json.load(f)
        print("✅ Loaded Alice's message from alice_message_to_bob.json")
    except FileNotFoundError:
        print("❌ File alice_message_to_bob.json not found!")
        return
    
    iv = bytes.fromhex(message_package['iv'])
    ciphertext = bytes.fromhex(message_package['ciphertext'])
    hmac_tag = bytes.fromhex(message_package['hmac'])
    
    print(f"\n📦 Received encrypted message:")
    print(f"  • IV: {iv.hex()}")
    print(f"  • Ciphertext: {ciphertext.hex()}")
    print(f"  • HMAC: {hmac_tag.hex()}")
    
    print(f"\n🔍 Verifying HMAC...")
    data_to_verify = iv + ciphertext
    computed_hmac = secure_msg.compute_hmac(data_to_verify)
    print(f"  • Computed HMAC: {computed_hmac.hex()}")
    print(f"  • Received HMAC:  {hmac_tag.hex()}")
    
    if computed_hmac == hmac_tag:
        print("  ✓ HMAC matches!")
    else:
        print("  ❌ HMAC does not match!")
        return
    
    print(f"\n🔓 Decrypting message...")
    plaintext = secure_msg.sym_dec(ciphertext, iv)
    
    print(f"\n✅ Message from Alice: '{plaintext.decode()}'")
    
    print(f"\n⏰ End timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n✅ All tasks completed successfully!")

if __name__ == "__main__":
    main()