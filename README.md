# Secure Messaging System

**ITIS 6200/8200 - Principles of Information Security and Privacy**  
**Manvitha Ayinampudi**  
**Fall 2025**

## What This Project Does

This is a two-party secure messaging system where Alice and Bob can exchange encrypted messages. The cool part is that they can establish a shared secret key even when talking over an insecure channel (like the internet), and then use that key to encrypt their messages so no one else can read them.

I implemented everything we learned in class:
- RSA digital signatures to make sure no one's pretending to be Alice or Bob
- Diffie-Hellman to agree on a secret key without actually sending the key
- A key derivation function to make that secret even stronger
- AES encryption with HMAC to keep messages secret and detect tampering

## Quick Start

### What You Need
- Python 3 (I used Python 3.9)
- The `cryptography` library

### Setup

```bash
# Clone this repo
git clone https://github.com/manvithaayinampudi/secure-messaging-project.git
cd secure-messaging-project

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the crypto library
pip install cryptography
```

### Running It

You need two terminal windows open side by side. Think of one as Alice and one as Bob.

**Terminal 1 (Alice):**
```bash
source venv/bin/activate
python alice.py
```

**Terminal 2 (Bob):**
```bash
source venv/bin/activate
python bob.py
```

Then just follow what the programs tell you! They'll save files to share data with each other, and you just need to press Enter at the right times.

## How It Works

### The Process

1. **Alice and Bob generate their keys** - Each gets their own RSA key pair for signing stuff
2. **They do a Diffie-Hellman exchange** - This is where they agree on a shared secret without actually sending it
3. **They sign everything** - This prevents man-in-the-middle attacks
4. **They verify each other's signatures** - Making sure they're really talking to who they think they are
5. **Both derive the same encryption key** - Using that shared secret
6. **Alice sends an encrypted message** - Using AES-256 with an HMAC tag
7. **Bob decrypts it** - After verifying the HMAC to make sure nothing was changed

### Technical Details

I used:
- **RSA-2048** for digital signatures
- **3072-bit prime** for Diffie-Hellman (the RFC 3526 one)
- **AES-256-CBC** for encryption
- **HMAC-SHA256** for message authentication
- **Encrypt-then-MAC** approach (learned this is more secure than MAC-then-encrypt)

## Files

```
alice.py                      # Alice's side of things
bob.py                        # Bob's side
README.md                     # You're reading it
alice_to_bob.json            # Generated when running - Alice's DH data
bob_to_alice.json            # Generated when running - Bob's DH data
alice_message_to_bob.json    # Generated when running - encrypted message
```

## Project Requirements

This project covers all six tasks from the assignment:

**Task 1: Digital Signatures**
- Key generation with RSA
- Signing messages
- Verifying signatures

**Task 2: Diffie-Hellman Key Exchange**
- Generate DH parameters
- Exchange public values with signatures
- Compute shared secret

**Task 3: Key Derivation**
- Hash the shared secret 10,000 times with SHA-256
- Get a strong 256-bit encryption key

**Task 4: PRNG**
- Initialize with current time
- Generate random IVs for encryption
- Demonstrate deterministic behavior

**Task 5: Secure Messaging**
- Encrypt with AES-256-CBC
- Compute HMAC for integrity
- Decrypt and verify

**Task 6: Tampering Detection (built-in)**
- HMAC verification catches any changes to the ciphertext

## Why I Made Certain Choices

**File-based communication instead of copy-paste:**
I originally tried having users copy and paste JSON between terminals, but it turned out to be a pain on Mac because of how the terminal handles multiline input. Using files is way cleaner and actually makes more sense for demonstrating the concepts.

**Encrypt-then-MAC:**
I went with encrypt-then-MAC instead of MAC-then-encrypt because that's what we discussed in class as being more secure. It prevents padding oracle attacks.

**10,000 iterations for KDF:**
This is standard practice. Makes it really hard for someone to brute force even if they somehow get the shared secret.

## Troubleshooting

**"ModuleNotFoundError: No module named 'cryptography'"**
- Make sure you activated the virtual environment: `source venv/bin/activate`
- Install the library: `pip install cryptography`

**"File not found" errors**
- Both programs need to run from the same directory
- Make sure Alice creates her file before Bob tries to read it
- Just follow the prompts and press Enter at the right times

**Shared secrets don't match**
- This means something went wrong with the signature verification
- Just restart both programs and try again

## What I Learned

Honestly, this project really helped me understand how all these cryptographic pieces fit together. In class we learned about each technique separately, but seeing how they all work together to create a secure communication channel was really cool.

The most interesting part was realizing why we need digital signatures on the Diffie-Hellman exchange. Without them, someone could intercept the exchange and do a man-in-the-middle attack. But with signatures, each party can verify they're really talking to who they think they are.

Also learned that getting crypto right is hard! There are so many little details that matter - like making sure to verify the HMAC before decrypting, or making sure the IV is truly random.

## Limitations

This is a class project, so it's not production-ready. Some things I'd need to add for real-world use:
- Proper certificate infrastructure for distributing public keys
- Forward secrecy (so if keys get compromised later, old messages stay safe)
- Actual network communication instead of files
- Better error handling
- Key rotation
- Protection against timing attacks

But for learning how this all works, I think it does the job pretty well!

## References

- Course lectures and notes from ITIS 6200/8200
- Python cryptography library docs: https://cryptography.io/
- RFC 3526 for the DH parameters
- NIST recommendations for key sizes

---

Feel free to reach out if you have questions about the implementation!
