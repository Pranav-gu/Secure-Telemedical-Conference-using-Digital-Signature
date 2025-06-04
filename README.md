# System Network Security

## Assignment 2 : Secure Telemedical Conference using Digital Signature

### Submitted by - Team 9
- Amogha A H (2021101007)
- Ishit Bansal (2021101083)
- Pranav Gupta (2021101095)


## Overview
This project implements a secure telemedical system where doctors and patients can communicate confidentially using cryptographic protocols. 

## Features
- **Secure authentication**: Patients and doctors authenticate using ElGamal cryptography.
- **Session key exchange**: Secure key exchange via ElGamal ensures confidentiality.
- **Encrypted communication**: AES-256 encryption is used for messages and consultation records.
- **Message integrity**: Cryptographic signatures validate message authenticity.
- **Session verification**: Time-stamped messages prevent replay attacks.

## Components
1. **Key Generation**
   - Uses ElGamal cryptosystem to generate public and private keys.
   - Ensures strong security by selecting a large prime number.
2. **Encryption & Decryption**
   - Messages are encrypted using ElGamal encryption and secured with AES-256.
   - Decryption uses modular inverse calculations.
3. **Authentication & Key Exchange**
   - Patients send authentication requests with encrypted session keys.
   - The doctor verifies timestamps, validates signatures, and establishes a session key.
   - Mutual authentication ensures both parties agree on a shared session key before communication begins.

## Running the System
   - Start the doctor server:
     ```bash
     python doctor.py
     ```
   - Start the patient clients:
     ```bash
     python patient1.py
     python patient2.py
     python patient3.py
     ```
## Communication Workflow
   - The patient requests authentication.
   - The doctor verifies and establishes a session key.
   - Secure messages are exchanged using AES-256.

## Security Considerations
- The system ensures secure authentication through digital signatures.
- Encryption protects against eavesdropping and unauthorized access.
- Timestamp-based verification prevents replay attacks.
- Patients are temporarily blocked after failed authentication attempts.
- Broadcasting - It is assumed that only 3 patients can join the group at once. Once there are 3 active connections, the doctor broadcasts a message which reaches the 3 patients. If any patient opts to switch out, only then a new broadcast message will be broadcasted to the patients, i.e. the Broadcasting is initiated only when the group of active connections changes.

## Performance Analysis

Here’s a brief explanation of the cryptographic primitives and their execution times:

| Cryptographic Primitive            | Time Taken (ms) |
|------------------------------------|----------------|
| **Key Generation (ElGamal) (n=10)**  | 0.024          |
| **Key Generation (ElGamal) (n=20)**  | 0.059          |
| **Key Generation (ElGamal) (n=50)**  | 0.121          |
| **Signing Data (ElGamal)**          | 0.019          |
| **Signature Verification**          | 0.030          |
| **AES-256 Encryption**              | 0.583          |
| **AES-256 Decryption**              | 0.451          |
| **Hash Computation (SHA-256)**      | 0.017          |
| **Hash Computation (SHA-512)**      | 0.049          |

### Explanation:
1. **Key Generation (ElGamal)**:  
   - This involves selecting a large prime number `p` and a generator `g`, making the discrete logarithm problem intractable.  
   - The value `n` represents the bit length used for generating the prime (`randprime(2^n, 2^(n+1))`). Larger values of `n` result in longer execution times.

2. **Signing Data (ElGamal)**:  
   - Uses the sender's private key to generate a signature for message integrity.  
   - Relatively fast compared to key generation.

3. **Signature Verification**:  
   - Uses the sender’s public key to check if a signature is valid.  
   - Slightly slower than signing but remains efficient.

4. **AES-256 Encryption & Decryption**:  
   - Encrypts and decrypts data using a 256-bit key for confidentiality.  
   - Encryption is slightly slower than decryption due to additional padding and processing.

5. **Hash Computation (SHA-256 & SHA-512)**:  
   - Produces a fixed-size digest to ensure data integrity.  
   - SHA-512 is slower than SHA-256 due to its larger output size and computational complexity.