# AES (Advanced Encryption Standard) 🔑
This repository is dedicated to the implementation of the Advanced Encryption Standard (AES), also known as Rijndael.
AES is a symmetric block cipher used by the US government and widely adopted worldwide. It provides strong security and is the successor to DES.
It supports key sizes of 128, 192, and 256 bits, operating on a fixed 128-bit (16-byte) data block. A good reference to understand this algorithm is: <a href="https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf">NIST FIPS 197</a>


## How to Run AES
This module provides a demonstration of the AES-128 algorithm (128-bit key, 10 rounds) for encryption and decryption of data. <br>

First, clone this repo and navigate to the root directory where demo_aes.py resides:

```
git clone git@github.com/Snafkin547/Cryptography.git
cd Cryptography/aes_module # Assuming this is your module directory
```

The core logic is contained within the AES class in the src/aes.py file. You may instantiate it and call the .encrypt method:

```
aes_inst = AES(key_int)
cipher_val, cipher_bytes = aes_inst.encrypt(plaintext_int)
```

The AES encryption and decryption methods require the input key and plaintext to be provided as single, large integers (up to 128 bits). 
The internal logic handles conversion to bytes.

## Example Usage: Encryption and Decryption

Putting this all together, you can craft your encryption and decryption routine like this: (The final assertion proves the symmetric nature of the algorithm by verifying the decrypted integer matches the original plaintext integer.)

```
from src.aes import AES
from src.utils import int_to_bitlist # Optional: for bit-level assertion

# 128-bit key and plaintext represented as integers
_key = 1235282586324778           # Example 128-bit key
int_str = 1987034928369859712     # Example 128-bit plaintext

# Initiate AES-128
aes_inst = AES(_key)

# AES encryption
cipher_val, cipher_bytes = aes_inst.encrypt(int_str)
assert len(cipher_bytes) == 16 # AES block size is 16 bytes (128 bits)
print(f"\nEncrypted value (Int): {cipher_val}")

# AES decryption
plain_val, plain_bytes = aes_inst.decrypt(cipher_bytes)
print(f"Decrypted value (Int): {plain_val}")

# Result and proof of symmetricity
print(f"\nOriginal Input (Int): {int_str}")
assert int_str == plain_val

```

## Implementation Details (Native Python)

The Data Encryption Standard (DES), a 56-bit encryption algorithm, was broken in record time through a joint effort by the Electronic Frontier Foundation and Distributed.Net.
This significant cryptographic achievement was accomplished in less than 23 hours, specifically in 22 hours and 15 minutes, in January 1999​​​​.  <br>

In response to its vulnerabilities, notably its short key length, an enhanced version called Triple DES (3DES) was introduced, utilizing multiple DES keys in sequence to significantly bolster security. 
This advanced version has gained approval from the National Institute of Standards and Technology (NIST) and is incorporated in numerous cryptographic standards, maintaining its relevance as a secure option for protecting sensitive data, particularly in legacy systems.

The following is the example code to demonstrate triple-DES algorithm:

```
from src import *

# Generate 64 bits input
input_size = 64
input_val, input_bits = generate_bit(input_size)

# Generate 64 bits input
keys = [8289481480542705629, 8289481480542225629, 9128814805426305629]

# Initiate DES
DES_inst = triple_DES(keys)

# Triple-DES encryption
enc_val, enc_bits = DES_inst.encrypt(input_bits)

# Triple-DES decryption
final_val, final_bits = DES_inst.decrypt(enc_bits)

# Result and proof of symmetricity
print(f"\ninput value     :{input_val}")
print(f"decrypted value :{final_val}")
assert final_val == input_val
```

## Code Formatting Standards
My project uses Black, a Python code formatter, to ensure uniform formatting across our codebase. 
Contributors are required to format their code using black . in the root directory before pushing to the repository. 

Additionally, we employ a GitHub Action that automatically checks for compliance with Black's formatting standards on each pull request. 
This check can prevent merging if the code does not meet the required standards. 
It's crucial to remember to run Black before pushing changes, as this not only keeps the code clean and readable but also facilitates the review and merging process by adhering to our automated checks.
