# Encrypted Images — BITSCTF Known-Plaintext Attack

## 1. Project Overview

The objective of this project is to decrypt an encrypted PNG image and recover a hidden flag in the format:

```text
BITSCTF{...}
```

The provided encryption algorithm uses a repeating 24-byte XOR key to encrypt an image. Before encryption, the original PNG file is padded so that its length is a multiple of 24 bytes.

Our goal is to exploit weaknesses in this encryption algorithm using a **Known-Plaintext Attack (KPA)**.

We are given prior knowledge of the PNG file format, specifically its first 16 bytes. This allows us to recover the first 16 bytes of the encryption key. We must then analyze the padding mechanism and the structure of PNG files to recover the remaining 8 bytes.

Once the complete 24-byte key is recovered, we can decrypt the image and extract the flag.

## Current Implementation Status

This branch implements the key-recovery half of the attack in `attack.py`. The provided `enc27-1-1.py` preserves the same algorithm but now uses Python 3 `bytes` so the encrypted output can be written to a binary file without a `str`-to-`bytes` type error.

### Completed

- Read the encrypted PNG as binary data and validate that its length is a positive multiple of 24.
- Recover the first 16 key bytes from the known PNG header.
- Test every padding length `L` from 1 through 24.
- For each candidate, let `M = len(ciphertext) - L` be the original PNG length:
  - XOR `ciphertext[M-12:M]` with the known `IEND` chunk to constrain key positions `(M-12+j) mod 24`.
  - XOR the final `L` ciphertext bytes with `L` to constrain key positions `(M+j) mod 24`.
  - Reject candidates whose recovered key bytes conflict.
- Return the unique complete 24-byte key and padding length; ambiguous candidates are reported rather than guessed.
- Cover all 24 padding lengths with synthetic `unittest` fixtures.

### Teammate Handoff

The following functions in `attack.py` are intentionally left as `NotImplementedError` stubs:

- `decrypt_image(ciphertext, key)`: decrypt with the repeating key and remove padding.
- `validate_png(data)`: verify the PNG signature, `IEND` chunk, and chunk CRCs.
- `extract_flag(data)`: find and return the `BITSCTF{...}` flag.

After those are implemented, save the recovered image and update the validation checklist below. Maple is optional for demonstrating the XOR math; Python's standard library is sufficient for the full implementation.

### Project Objectives

- Understand the provided XOR encryption algorithm.
- Identify weaknesses in the encryption implementation.
- Recover the encryption key using a known-plaintext attack.
- Analyze the padding mechanism to recover the remaining key bytes.
- Decrypt the original PNG image.
- Extract the hidden BITSCTF flag.

---

## 2. Provided Encryption Algorithm

The assignment provides the following Python encryption implementation:

```python
#!/usr/bin/env python

def supa_encryption(s1, s2):
    res = [chr(0)] * 24

    for i in range(len(res)):
        q = ord(s1[i])
        d = ord(s2[i])
        k = q ^ d
        res[i] = chr(k)

    res = ''.join(res)
    return res


def add_pad(msg):
    L = 24 - len(msg) % 24
    msg += chr(L) * L
    return msg


with open('fullhd.png', 'rb') as f:
    data = f.read()

data = add_pad(data)

with open('key.txt') as f:
    key = f.read()

enc_data = ''

for i in range(0, len(data), 24):
    enc = supa_encryption(data[i:i+24], key)
    enc_data += enc

with open('BITSCTFfullhd.png', 'wb') as f:
    f.write(enc_data)
```

The committed `enc27-1-1.py` is a Python 3 `bytes` equivalent of this snippet. It reads `key.txt` in binary mode and accumulates output in a `bytearray`, which avoids passing a `str` to `write()` on a file opened with `"wb"`.

### 2.1 How the Encryption Works

There are three main operations:

1. Read the original PNG image.
2. Add padding until the image's length is divisible by 24 bytes.
3. XOR each 24-byte block with the same 24-byte key.

The encryption operation is:

\[
C_i=P_i\oplus K_i
\]

Where:

- \(C_i\): Ciphertext byte.
- \(P_i\): Original plaintext byte.
- \(K_i\): Encryption key byte.
- \(\oplus\): Bitwise XOR.

The same 24-byte key is reused for every block.

### 2.2 Padding Mechanism

The padding function is:

```python
def add_pad(msg):
    L = 24 - len(msg) % 24
    msg += chr(L) * L
    return msg
```

The padding length is calculated using:

\[
L=24-(\text{message length}\bmod24)
\]

The algorithm appends `L` bytes, each containing the value `L`.

Examples:

| Bytes needed | Padding added          |
| ------------ | ---------------------- |
| 1            | `01`                   |
| 4            | `04 04 04 04`          |
| 8            | Eight `08` bytes       |
| 16           | Sixteen `10` bytes     |
| 24           | Twenty-four `18` bytes |

**Important:** If the original file is already divisible by 24, the algorithm adds an entire 24-byte padding block.

---

## 3. Attack Strategy: Known-Plaintext Attack

A known-plaintext attack works by using information about the original plaintext and comparing it with the corresponding ciphertext.

The key recovery equation is:

\[
C=P\oplus K
\]

Rearranging:

\[
\boxed{K=C\oplus P}
\]

This works because XOR is reversible:

\[
(A\oplus B)\oplus B=A
\]

Our attack consists of two primary stages.

### Stage 1: Recover the First 16 Bytes of the Key

PNG files have a standardized file signature and initial header.

We are given the following 16 bytes:

```python
png_header = bytes([
    0x89, 0x50, 0x4e, 0x47,
    0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52
])
```

Since we know the first 16 bytes of the original PNG, we can XOR them with the first 16 bytes of the encrypted image.

\[
K_i=C_i\oplus P_i
\]

Python implementation:

```python
with open("BITSCTFfullhd.png", "rb") as f:
    ciphertext = f.read()

png_header = bytes([
    0x89, 0x50, 0x4e, 0x47,
    0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52
])

key = bytearray(24)

for i in range(16):
    key[i] = ciphertext[i] ^ png_header[i]

print("Recovered first 16 key bytes:", key[:16].hex())
```

At this point, we have recovered:

```text
K = [16 known bytes] + [8 unknown bytes]
```

### Stage 2: Recover the Remaining 8 Bytes

The remaining key bytes can be recovered by analyzing the padding at the end of the original PNG.

The padding function guarantees that the final bytes of the plaintext are known.

For example, if the padding length is 8, the final eight plaintext bytes will be:

```text
08 08 08 08 08 08 08 08
```

The corresponding ciphertext bytes can be XORed with `0x08` to recover their respective key bytes.

\[
K_i=C_i\oplus L
\]

Where `L` is the padding length.

We can also use the standardized PNG `IEND` chunk, which consists of the following 12 bytes:

```python
png_end = bytes([
    0x00, 0x00, 0x00, 0x00,
    0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82
])
```

The final PNG chunk appears immediately before the padding, assuming the image has no trailing data.

By combining the known `IEND` chunk and the padding bytes, we can recover additional key bytes.

We do not initially know the padding length, so we must test possible values from 1 through 24.

For each candidate:

1. Assume the last `L` plaintext bytes contain padding.
2. Recover the corresponding key bytes.
3. Use the known `IEND` chunk to recover additional key bytes.
4. Compare overlapping recovered key bytes for consistency.
5. Reject candidates that produce conflicting key values.

The correct candidate should produce a consistent 24-byte key.

---

## 4. Decryption Algorithm

Once all 24 bytes of the key have been recovered, decryption is straightforward.

The encryption operation is:

\[
C=P\oplus K
\]

The decryption operation is identical:

\[
\boxed{P=C\oplus K}
\]

Because the key repeats every 24 bytes, we use:

\[
P*i=C_i\oplus K*{i\bmod24}
\]

Python implementation:

```python
plaintext = bytearray()

for i in range(len(ciphertext)):
    plaintext.append(ciphertext[i] ^ key[i % 24])
```

After decryption, we must remove the padding.

```python
L = plaintext[-1]
plaintext = plaintext[:-L]
```

Finally, save the decrypted image:

```python
with open("decrypted.png", "wb") as f:
    f.write(plaintext)
```

The resulting image should be a valid PNG containing the hidden flag.

---

## 5. Project Implementation Roadmap

We will approach the assignment in the following order.

| Step | Task                           | Expected Result                | Status    |
| ---- | ------------------------------ | ------------------------------ | --------- |
| 1    | Obtain encrypted PNG           | `BITSCTFfullhd.png`            | Pending   |
| 2    | Analyze encryption algorithm   | Understand XOR and padding     | Complete  |
| 3    | Recover first 16 key bytes     | Partial encryption key         | Complete  |
| 4    | Analyze final ciphertext block | Identify padding possibilities | Complete  |
| 5    | Recover remaining 8 key bytes  | Complete 24-byte key           | Complete  |
| 6    | Validate recovered key         | Confirm consistent plaintext   | Pending   |
| 7    | Decrypt image                  | `decrypted.png`                | Pending   |
| 8    | Extract hidden flag            | `BITSCTF{...}`                 | Pending   |

---

## 6. Project File Structure

Current directory organization:

```text
EncryptedImage/
│
├── ReadME.md
├── attack.py
├── enc27-1-1.py
├── BITSCTFfullhd.png
│
└── tests/
    └── test_attack.py
```

`.gitignore` is also present to exclude Python caches, virtual environments, and the generated decrypted image. `BITSCTFfullhd.png` is not currently committed; place the provided ciphertext in the project root before running the CLI.

### File Responsibilities

- `ReadME.md`: Project documentation, attack explanation, and teammate handoff.
- `attack.py`: All attack code, teammate stubs, and the command-line interface.
- `enc27-1-1.py`: Python 3 reference implementation of the original encryption script.
- `BITSCTFfullhd.png`: Encrypted input PNG supplied by the assignment.
- `tests/test_attack.py`: Synthetic tests for header and full-key recovery.

---

## 7. Getting Started

### Requirements

- Python 3.10+
- Encrypted PNG file: `BITSCTFfullhd.png` in the project root, or another path passed to the CLI
- Basic understanding of XOR operations and byte manipulation.

Maple may also be used to demonstrate the mathematical operations, but Python is recommended for the actual byte-level attack.

### Environment Setup

Clone or download the project repository.

Navigate into the project directory:

```bash
cd Encrypted-Images
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

**macOS/Linux:**

```bash
source venv/bin/activate
```

**Windows:**

```bash
venv\Scripts\activate
```

No additional Python packages are required for the basic implementation.

Run the key-recovery CLI:

```bash
python3 attack.py
```

Or provide the ciphertext path explicitly:

```bash
python3 attack.py BITSCTFfullhd.png
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

---

## 8. Validation and Testing

We should verify the following before considering the attack successful:

- [x] The encrypted image is read correctly as binary data.
- [x] The first 16 key bytes are recovered correctly.
- [x] The padding length is identified.
- [x] The remaining 8 key bytes are recovered.
- [x] The complete key contains exactly 24 bytes.
- [ ] The decrypted image begins with the correct PNG signature.
- [ ] The decrypted image ends with the correct `IEND` chunk.
- [ ] Padding is removed correctly.
- [ ] The decrypted image opens successfully.
- [ ] The BITSCTF flag is recovered.

Useful PNG validation:

```python
with open("decrypted.png", "rb") as f:
    data = f.read()

assert data[:8] == bytes([
    0x89, 0x50, 0x4e, 0x47,
    0x0d, 0x0a, 0x1a, 0x0a
])

assert data[-12:] == bytes([
    0x00, 0x00, 0x00, 0x00,
    0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82
])

print("PNG validation successful!")
```

---

## 9. Cryptographic Weaknesses

The primary weakness in this encryption algorithm is the reuse of a fixed XOR key.

The same 24-byte key encrypts every block, meaning:

\[
C_1=P_1\oplus K
\]

\[
C_2=P_2\oplus K
\]

Consequently:

\[
C_1\oplus C_2=P_1\oplus P_2
\]

This leaks relationships between plaintext blocks.

Additionally, predictable file formats such as PNG provide known plaintext that can be used to recover key material.

The padding mechanism provides another source of predictable plaintext.

### Key Takeaways

1. XOR encryption is reversible using the same key.
2. Reusing a fixed XOR key across multiple blocks is insecure.
3. Known file signatures can reveal encryption key bytes.
4. Predictable padding can reveal additional key bytes.
5. File format specifications can be leveraged in cryptographic attacks.

---

## 10. Final Deliverable

Our final deliverable should include:

- The Python implementation of the attack.
- The recovered 24-byte encryption key.
- The identified padding length.
- The decrypted PNG image.
- The recovered `BITSCTF{...}` flag.
- An explanation of the known-plaintext attack and why it works.

**Project Goal:** Demonstrate how weaknesses in a poorly designed XOR encryption scheme can be exploited using known plaintext and predictable padding to recover an encrypted image without knowing the original encryption key.
