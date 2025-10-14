# Secure Messaging Project

**Course:** ITIS 6200/8200 - Principles of Information Security and Privacy  
**Author:** [Your Name]  
**Date:** October 2025  

## 📋 Project Overview

This project implements a secure two-party messaging system demonstrating core cryptographic concepts including:

- **Digital Signatures (RSA)** - Authentication and integrity
- **Diffie-Hellman Key Exchange** - Secure key establishment
- **Key Derivation Functions (KDF)** - Strong encryption key generation
- **Pseudo-Random Number Generation (PRNG)** - IV/nonce generation
- **Authenticated Encryption** - AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

The system allows Alice and Bob to establish a shared secret over an insecure channel, derive a strong encryption key, and exchange encrypted messages with both confidentiality and integrity guarantees.

---

## 🏗️ Project Structure

```
secure_messaging_project/
│
├── alice.py                      # Alice's terminal program
├── bob.py                        # Bob's terminal program
├── README.md                     # This file
│
├── venv/                         # Virtual environment (not in repo)
│
└── Generated Files (during execution):
    ├── alice_to_bob.json         # Alice's DH public value & signature
    ├── bob_to_alice.json         # Bob's DH public value & signature
    └── alice_message_to_bob.json # Encrypted message from Alice
```

---

## 🛠️ Prerequisites

- **Python 3.7+** (Python 3.8 or higher recommended)
- **pip** (Python package manager)
- **Git** (for cloning the repository)

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/secure-messaging-project.git
cd secure-messaging-project
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate Virtual Environment

**On macOS/Linux:**
```bash
source venv/bin/activate
```

**On Windows:**
```bash
venv\Scripts\activate
```

You should see `(venv)` appear at the start of your terminal prompt.

### 4. Install Dependencies

```bash
pip install cryptography
```

---

## 🚀 How to Run

### Quick Start

1. **Open two terminal windows** side-by-side
2. **Activate virtual environment in both terminals**
3. **Run Alice in Terminal 1, Bob in Terminal 2**
4. **Follow the interactive prompts**

### Detailed Step-by-Step Execution

#### Terminal 1 (Alice):

```bash
# Navigate to project directory
cd secure-messaging-project

# Activate virtual environment
source venv/bin/activate

# Run Alice's program
python alice.py
```

#### Terminal 2 (Bob):

```bash
# Navigate to project directory
cd secure-messaging-project

# Activate virtual environment
source venv/bin/activate

# Run Bob's program
python bob.py
```

### Execution Flow

1. **Task 1 & 2:** Both programs generate keys and perform DH exchange
   - Alice creates `alice_to_bob.json` → Press Enter when prompted
   - Bob reads the file → Press Enter when prompted
   - Bob creates `bob_to_alice.json`
   - Alice reads the file → Press Enter when prompted

2. **Task 3 & 4:** Both programs automatically derive keys and test PRNG

3. **Task 5:** Message exchange
   - Alice prompts: "Enter message to send to Bob"
   - Type your message (e.g., "Hello Bob!")
   - Alice creates `alice_message_to_bob.json`
   - Bob waits → Press Enter when prompted
   - Bob decrypts and displays the message

---

## 📂 File Communication Method

This implementation uses **JSON files** for data exchange between Alice and Bob to avoid terminal copy-paste issues. The files are automatically created in the project directory:

| File | Creator | Content | Reader |
|------|---------|---------|--------|
| `alice_to_bob.json` | Alice | DH public value, signature, public key | Bob |
| `bob_to_alice.json` | Bob | DH public value, signature, public key | Alice |
| `alice_message_to_bob.json` | Alice | Encrypted message (IV, ciphertext, HMAC) | Bob |

---

## 🔬 Technical Implementation Details

### Task 1: Digital Signatures

**Algorithm:** RSA-2048 with PSS padding  
**Hash Function:** SHA-256  

**Functions:**
- `generate_keys()` - Generates RSA public/private key pairs
- `sign(message, private_key)` - Signs message with private key
- `verify(message, signature, public_key)` - Verifies signature (returns 1/0)

**Purpose:** Authenticate parties and prevent man-in-the-middle attacks during key exchange.

---

### Task 2: Diffie-Hellman Key Exchange

**Parameters:**
- Prime (p): 3072-bit safe prime (RFC 3526 Group 15)
- Generator (g): 2

**Process:**
1. Alice generates secret `a`, computes `g^a mod p`
2. Bob generates secret `b`, computes `g^b mod p`
3. Both sign their public values with RSA private keys
4. Exchange signed public values via JSON files
5. Verify signatures using RSA public keys
6. Compute shared secret: `g^ab mod p`

**Security:** Signed DH prevents active man-in-the-middle attacks.

---

### Task 3: Key Derivation Function (KDF)

**Algorithm:** Iterative SHA-256 hashing  
**Iterations:** 10,000  
**Output:** 256-bit (32-byte) encryption key

**Process:**
```
key = shared_secret
for i in range(10000):
    key = SHA256(key)
```

**Purpose:** Strengthen the shared secret into a cryptographically strong encryption key.

---

### Task 4: Pseudo-Random Number Generator (PRNG)

**Algorithm:** Hash-based PRNG using SHA-256  
**Seed:** Current system time (microseconds)  

**Functions:**
- `seed(value)` - Initialize PRNG state
- `reseed(entropy)` - Add additional randomness
- `generate(num_bytes)` - Generate random bytes

**Demonstration:**
- Random sequence generation
- Deterministic behavior (same seed → same output)
- Different seeds produce different sequences

---

### Task 5: Authenticated Encryption

**Encryption:** AES-256-CBC  
**Authentication:** HMAC-SHA256  
**Mode:** Encrypt-then-MAC  

**Functions:**
- `sym_enc(plaintext, iv)` - AES-256-CBC encryption with PKCS#7 padding
- `sym_dec(ciphertext, iv)` - AES-256-CBC decryption
- `compute_hmac(data)` - HMAC-SHA256 computation
- `authenticated_encrypt(plaintext)` - Complete Encrypt-then-MAC
- `authenticated_decrypt(iv, ct, hmac)` - Verify HMAC then decrypt

**Message Format:**
```json
{
  "iv": "hex_encoded_initialization_vector",
  "ciphertext": "hex_encoded_encrypted_data",
  "hmac": "hex_encoded_authentication_tag"
}
```

**Security Properties:**
- **Confidentiality:** AES-256 ensures message secrecy
- **Integrity:** HMAC detects any tampering
- **Authentication:** Only parties with the shared key can encrypt/decrypt

---

## 📸 Screenshots for Submission

The following screenshots should be captured during execution (with visible timestamps):

### Task 1: Digital Signatures
- [ ] Alice's public key generation
- [ ] Bob's public key generation
- [ ] Signature verification test (returns 1)

### Task 2: Diffie-Hellman
- [ ] Public parameters (p, g)
- [ ] Alice's DH public value and signature
- [ ] Bob's DH public value and signature
- [ ] Alice verifying Bob's signature (returns 1)
- [ ] Bob verifying Alice's signature (returns 1)
- [ ] Alice's computed shared secret
- [ ] Bob's computed shared secret (should match Alice's)

### Task 3: Key Derivation
- [ ] Derived encryption key (both sides should match)

### Task 4: PRNG
- [ ] Random sequence output
- [ ] Deterministic test (same seed produces identical sequences)
- [ ] Different seed test (different seeds produce different sequences)

### Task 5: Secure Messaging
- [ ] Alice's plaintext message
- [ ] Alice's encryption output (IV, ciphertext, HMAC)
- [ ] Bob's HMAC verification success
- [ ] Bob's decrypted message (matches Alice's plaintext)

---

## 🔐 Security Analysis

### Threats Mitigated

1. **Man-in-the-Middle (MITM) Attacks**
   - Digital signatures authenticate DH public values
   - Attacker cannot forge signatures without private keys

2. **Eavesdropping**
   - DH ensures shared secret never transmitted
   - AES-256 provides strong confidentiality

3. **Message Tampering**
   - HMAC-SHA256 detects any modifications
   - Encrypt-then-MAC prevents padding oracle attacks

4. **Replay Attacks**
   - Fresh random IVs prevent ciphertext reuse
   - PRNG ensures unpredictable IVs

### Known Limitations

This is an **educational prototype** with the following limitations:

- No certificate authority (CA) for public key distribution
- No forward secrecy (compromised private keys reveal past sessions)
- File-based communication (not real network sockets)
- No session management or key rotation
- No protection against timing attacks
- Simplified PRNG (not cryptographically secure for production)

---

## 🧪 Testing

### Verify Installation

```bash
python -c "import cryptography; print('✓ Cryptography library installed')"
```

### Test Individual Components

You can test the cryptographic components independently by importing the classes:

```python
from alice import DigitalSignature, DiffieHellman

# Test signature
ds = DigitalSignature()
priv, pub = ds.generate_keys()
sig = ds.sign("test", priv)
print(ds.verify("test", sig, pub))  # Should print 1
```

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'cryptography'"

**Solution:**
```bash
pip install cryptography
# or
pip3 install cryptography
```

### Issue: "File not found" errors

**Solution:**
- Ensure both programs are running in the same directory
- Check that Alice creates files before Bob tries to read them
- Press Enter at the correct prompts

### Issue: Shared secrets don't match

**Solution:**
- Restart both programs from the beginning
- Ensure signatures verify successfully (returns 1)
- Check that no errors occurred during DH exchange

### Issue: HMAC verification failed

**Solution:**
- Ensure both Alice and Bob have the same shared secret
- Check that encryption key derivation succeeded
- Verify no file corruption occurred

---

## 📚 Dependencies

- **cryptography (≥41.0.0)** - Modern cryptographic library
  - RSA key generation and signatures
  - AES encryption/decryption
  - Key serialization

- **Python Standard Library:**
  - `hashlib` - SHA-256 hashing
  - `hmac` - HMAC computation
  - `secrets` - Secure random number generation
  - `json` - Data serialization
  - `base64` - Binary data encoding
  - `time` - Timestamps

---

## 📖 Learning Outcomes

By completing this project, you will understand:

1. How digital signatures authenticate communicating parties
2. How Diffie-Hellman establishes shared secrets over insecure channels
3. Why key derivation functions strengthen cryptographic keys
4. The importance of randomness in cryptographic protocols
5. How authenticated encryption provides both confidentiality and integrity
6. The difference between Encrypt-then-MAC and MAC-then-Encrypt
7. Real-world application of cryptographic primitives

---

## 📝 Code Quality

- **Type Safety:** Clear type annotations in function signatures
- **Documentation:** Comprehensive docstrings for all classes and methods
- **Error Handling:** Try-except blocks for file I/O and cryptographic operations
- **Modularity:** Separate classes for each cryptographic component
- **Readability:** Clear variable names and logical code structure

---

## 🔄 Future Enhancements

Potential improvements for production use:

- [ ] Implement certificate-based PKI for public key distribution
- [ ] Add forward secrecy with ephemeral keys
- [ ] Use actual network sockets instead of files
- [ ] Implement key rotation and session management
- [ ] Add GUI for better user experience
- [ ] Use cryptographically secure PRNG (CSPRNG)
- [ ] Implement additional cipher modes (GCM, ChaCha20-Poly1305)
- [ ] Add comprehensive unit tests
- [ ] Performance optimization for large messages

---

## 📄 License

This project is for educational purposes as part of ITIS 6200/8200 coursework.

---

## 🙏 Acknowledgments

- Course: ITIS 6200/8200 - Principles of Information Security and Privacy
- Institution: UNC Charlotte
- Cryptography Library: Python Cryptographic Authority
- References: Applied Cryptography by Bruce Schneier, Cryptography Engineering by Ferguson, Schneier, and Kohno

---

## 📧 Contact

**Student:** [Your Name]  
**Email:** [your.email@charlotte.edu]  
**GitHub:** [https://github.com/YOUR_USERNAME](https://github.com/YOUR_USERNAME)

---

## 🎓 Academic Integrity

This project was completed individually as part of the course requirements. All code is original work, and cryptographic libraries are used as permitted by the assignment guidelines.

---

**Last Updated:** October 2025
