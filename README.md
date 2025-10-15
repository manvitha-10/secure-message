# Secure Messaging System

**Course**: ITIS 6200/8200 Principles of Information Security and Privacy  
**Project**: Secure Messaging Prototype Implementation  
**Student**: Manvitha Ayinampudi  
**Semester**: Fall 2025

## What This Project Is About

This project demonstrates a complete secure communication system between two parties (Alice and Bob). I built this to understand how real-world encrypted messaging works by implementing the fundamental cryptographic building blocks from scratch.

The system allows Alice and Bob to:
- Establish a shared encryption key without ever transmitting it directly
- Verify each other's identities to prevent impersonation
- Exchange encrypted messages that guarantee both secrecy and tamper-detection

## Repository Structure

```
secure_messaging_project/
│
├── alice.py                          # Alice's communication program
├── bob.py                            # Bob's communication program
├── README.md                         # Project documentation
│
├── venv/                             # Python virtual environment
│
└── Runtime Files (auto-generated):
    ├── alice_to_bob.json            # Alice's signed DH public value
    ├── bob_to_alice.json            # Bob's signed DH public value
    └── alice_message_to_bob.json    # Encrypted message package
```

## Getting Started

### Prerequisites

You'll need Python 3.7+ installed. I developed this using Python 3.9 on macOS.

### Installation Steps

1. **Clone the repository**
```bash
git clone https://github.com/manvithaayinampudi/secure-messaging-project.git
cd secure-messaging-project
```

2. **Set up virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install cryptography
```

### Running the Program

This program needs two terminal windows running simultaneously - one for Alice and one for Bob.

**Terminal Window 1 (Alice's side):**
```bash
cd secure_messaging_project
source venv/bin/activate
python alice.py
```

**Terminal Window 2 (Bob's side):**
```bash
cd secure_messaging_project
source venv/bin/activate
python bob.py
```

**Important**: Both programs communicate through JSON files that are automatically created in the project directory. Just follow the on-screen prompts and press Enter when instructed.

## How the Communication Works

### The Exchange Process

**Phase 1: Authentication Setup**
- Both Alice and Bob generate their own RSA key pairs
- These are used to sign messages and prove identities

**Phase 2: Key Agreement**
- Alice generates a random secret and computes her public Diffie-Hellman value
- She signs this value and saves it to a file
- Bob reads Alice's file, verifies her signature, and generates his own DH value
- Bob signs his value and saves it for Alice
- Alice reads Bob's file and verifies his signature
- Both compute the same shared secret independently

**Phase 3: Key Strengthening**
- Both parties run the shared secret through 10,000 rounds of SHA-256
- This produces a strong 256-bit encryption key

**Phase 4: Message Exchange**
- Alice encrypts her message using AES-256 in CBC mode
- She computes an HMAC tag over the encrypted data
- Everything is saved to a file for Bob
- Bob verifies the HMAC before decrypting
- Bob successfully reads the original message

## Implementation Details

### Task 1: RSA Digital Signatures
I implemented a complete digital signature system:
- **Algorithm**: RSA with 2048-bit keys
- **Signature scheme**: PSS padding with SHA-256
- **Purpose**: Authenticate DH public values to prevent man-in-the-middle attacks

Functions implemented:
- `generate_keys()` - Creates RSA public/private key pair
- `sign(message, private_key)` - Signs messages
- `verify(message, signature, public_key)` - Verifies signatures (returns 1 for valid, 0 for invalid)

### Task 2: Diffie-Hellman Key Exchange
Built a signed key exchange protocol:
- **Parameters**: Using RFC 3526 Group 15 (3072-bit prime)
- **Generator**: g = 2
- **Security**: All public values are digitally signed

Key functions:
- `generate_private_key()` - Creates random secret
- `compute_public_value()` - Computes g^secret mod p
- `compute_shared_secret()` - Derives g^ab mod p

### Task 3: Key Derivation Function
Strengthens the shared secret into an encryption key:
- **Method**: Iterated SHA-256 hashing
- **Iterations**: 10,000 rounds
- **Output**: 32-byte key suitable for AES-256

This approach is similar to PBKDF2 but simplified for educational purposes.

### Task 4: Pseudo-Random Number Generator
Created a deterministic PRNG for generating initialization vectors:
- **Base**: SHA-256 hash chaining
- **Seed**: System time in microseconds
- **Features**: Demonstrated both randomness and reproducibility

The PRNG shows:
- Random-looking output sequences
- Same seed produces identical sequences (determinism)
- Different seeds produce different sequences

### Task 5: Authenticated Encryption
Implemented the Encrypt-then-MAC construction:
- **Encryption**: AES-256 in CBC mode with PKCS#7 padding
- **MAC**: HMAC-SHA256
- **IV**: 16 random bytes from PRNG

Functions:
- `sym_enc()` - AES-256-CBC encryption
- `sym_dec()` - AES-256-CBC decryption
- `compute_hmac()` - HMAC tag generation
- `authenticated_encrypt()` - Combined encrypt + authenticate
- `authenticated_decrypt()` - Verify + decrypt

## Why File-Based Communication?

Initially, I tried implementing this with terminal copy-paste between Alice and Bob. However, I ran into issues with long JSON strings getting truncated by the terminal buffer on macOS. The file-based approach is actually cleaner because:
- No copy-paste errors or truncation
- Files can be easily inspected for debugging
- Better simulates real network packet exchange
- Easier to demonstrate for grading

## Security Analysis

**What's Protected:**
- ✅ Message confidentiality (AES-256)
- ✅ Message integrity (HMAC-SHA256)
- ✅ Identity verification (RSA signatures)
- ✅ Man-in-the-middle protection (signed DH exchange)
- ✅ Replay attack resistance (random IVs)

**Known Limitations:**
- This is an educational implementation, not production code
- No certificate authority for public key distribution
- No forward secrecy (ephemeral keys not implemented)
- File-based communication instead of real sockets
- Simplified PRNG (not cryptographically secure for production use)
- No key rotation or session management

## Common Issues and Fixes

**Problem**: `ModuleNotFoundError: No module named 'cryptography'`  
**Fix**: Activate the virtual environment first, then install: `pip install cryptography`

**Problem**: "File not found" errors during execution  
**Fix**: Make sure both programs run from the same directory and that Alice creates her file before Bob tries to read it

**Problem**: Shared secrets don't match  
**Fix**: This usually means signature verification failed. Restart both programs and make sure both successfully verify each other's signatures (should show "1")

**Problem**: HMAC verification fails  
**Fix**: Ensure both parties completed key derivation successfully and have matching encryption keys

## What I Learned

This project really connected the theory from lectures to practical implementation. Some key takeaways:

1. **Layered security is essential** - Each cryptographic primitive solves a specific problem (signatures for authentication, DH for key agreement, AES for confidentiality, HMAC for integrity)

2. **Order matters** - Using Encrypt-then-MAC instead of MAC-then-Encrypt prevents certain attacks. Small implementation choices have big security implications.

3. **Key management is hard** - Even in this simplified two-party scenario, managing public keys, shared secrets, and encryption keys requires careful coordination.

4. **Details matter in crypto** - Things like proper padding, random IVs, and signature verification all need to be done correctly or the entire system fails.

## Testing the Implementation

To verify everything works:

1. **Test signatures**: The programs should show verification returning 1 for correct keys
2. **Check shared secrets**: Alice and Bob should compute identical shared secret values
3. **Verify encryption keys**: Both parties should derive the same encryption key (shown in hex)
4. **Test messaging**: Bob should successfully decrypt and display Alice's original message

## Technologies Used

- **Python 3.9** - Main programming language
- **cryptography library** - Provides RSA, AES, and cryptographic primitives
- **hashlib** - SHA-256 hashing
- **hmac** - HMAC computation
- **secrets** - Secure random number generation
- **json** - Data serialization for file exchange

## Future Improvements

If I were to extend this project:
- Implement a proper PKI with certificate authorities
- Add forward secrecy using ephemeral Diffie-Hellman keys
- Replace files with actual network sockets
- Add session management and key rotation
- Implement perfect forward secrecy
- Add support for multiple message exchanges
- Include a GUI for better usability

## Academic Resources

- ITIS 6200/8200 Course Materials
- Python Cryptography Documentation: https://cryptography.io/
- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
- NIST Cryptographic Standards



*This project was completed as part of ITIS 6200/8200 coursework. All implementations follow course guidelines and use industry-standard cryptographic libraries.*
