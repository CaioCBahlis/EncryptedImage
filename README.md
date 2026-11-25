# MAD 4472 — Encrypted Image Project

This repository contains our group's solution, Maple decryption script, local test harness, and submission write-up for the **Encrypted Image** cryptography project.

---

## 1. What Is the Problem?

We are given a Python encryption script (`enc27-1-1.py`) and an encrypted PNG file (`BITSCTFfullhd.png`) that hides a flag of the format `BITSCTF{...}`.

Looking at `enc27-1-1.py`, the encryption algorithm works in two steps:

1. **PKCS#7-style Padding (`add_pad`):**
   Computes the padding length:
   $$L = 24 - (\text{len}(\text{msg}) \bmod 24), \quad 1 \le L \le 24$$
   and appends $L$ copies of the byte value $L$ to the end of the PNG file so the total length $n$ is always a multiple of 24 bytes.
2. **24-Byte Repeating-Key XOR (`supa_encryption`):**
   Splits the padded data into 24-byte blocks and XORs every block with the **same** secret 24-byte key $K = (K_1, K_2, \dots, K_{24})$:
   $$C_i = P_i \oplus K_{((i-1) \bmod 24) + 1}$$

### Why Is It Vulnerable?
Reusing the same 24-byte XOR key across every block turns the cipher into a repeating-key (many-time pad) cipher. Because XOR is self-inverse, **any known plaintext byte immediately reveals the corresponding key byte**:
$$K_i = P_i \oplus C_i$$

Even though the keyspace has $2^{192}$ possibilities (infeasible to brute-force), PNG files have fixed, predictable bytes at both the beginning and the end.

---

## 2. How Our Attack Recovers All 24 Key Bytes

### Step A: Recover Key Bytes `1..16` (Known PNG Header)
Every valid PNG file begins with the same 16 bytes (8-byte PNG signature + 4-byte `IHDR` length `13` + 4-byte `IHDR` chunk type):

```text
Hex:     89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52
Decimal: 137 80 78 71 13 10 26 10 0 0 0 13 73 72 68 82
```

XORing these 16 known bytes with the first 16 bytes of `BITSCTFfullhd.png` gives `key[1]` through `key[16]`.

### Step B: Recover Key Bytes `17..24` (PNG `IEND` Trailer + Padding)
Every valid PNG file ends with the fixed 12-byte `IEND` chunk:

```text
Hex:     00 00 00 00 49 45 4E 44 AE 42 60 82
Decimal: 0 0 0 0 73 69 78 68 174 66 96 130
```

Because `add_pad` appends $L$ bytes of value $L$ immediately after `IEND`, the final $12 + L$ bytes of the padded plaintext are completely known for any candidate $L \in \{1, 2, \dots, 24\}$:

```text
tail(L) = [0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130, L, L, ..., L]
           |<------------- 12-byte IEND -------------->| |<- L bytes ->|
```

1. Since $12 + L \ge 13$ and total length $n$ is a multiple of 24, `tail(L)` always overlaps with at least 5 positions aligned to the already-known key bytes `key[1..16]`.
2. Our Maple script tests each $L$ from `1` to `24` and checks whether `Xor(ct[pos], tail[j]) = key[kidx]` at every overlapping position with `kidx <= 16`.
3. Only the true padding length $L$ satisfies all overlapping checks.
4. Since $n$ is a multiple of 24, the **last 8 bytes of the file** always align with `key[17..24]`. XORing the last 8 bytes of ciphertext with the last 8 bytes of `tail(L)` recovers `key[17..24]`.

### Step C: Decrypt and Strip Padding
With all 24 bytes of `key` recovered:
1. XOR each ciphertext byte from `1` to `n - pad_len` with `key[((i - 1) mod 24) + 1]`.
2. Drop the final `pad_len` padding bytes.
3. Convert unsigned byte values (`0..255`) back to signed 8-bit integers (`-128..127`) for Maple's `FileTools:-Binary:-WriteFile`, and write `decrypted.png`.

---

## 3. Project File Structure

```text
EncryptedImage/
├── README.md                  # This group guide
├── Relevance_Statement.txt    # Submission Flag placeholder + Relevance Statement
├── enc27-1-1.py               # Original encryption algorithm provided in the prompt
├── decrypt_png.mpl            # Commented Maple script (CLI-ready)
├── decrypt_png.mw             # Commented Maple worksheet (Maple Desktop GUI)
└── crypto_test/               # Self-contained local test environment
    ├── make_test.py           # Encrypts test.png -> BITSCTFfullhd.png with a known key
    ├── test.png               # Sample PNG input
    ├── BITSCTFfullhd.png      # Encrypted test PNG
    └── decrypted.png          # Decrypted output produced by Maple (matches test.png)
```

---

## 4. How to Decrypt the Real Image (`BITSCTFfullhd.png`)

Once we have the official `BITSCTFfullhd.png` from Canvas / Prof. Biasse, place it in the root folder (`EncryptedImage/`).

### Option A: Maple Desktop GUI (`decrypt_png.mw`)
1. Open `decrypt_png.mw` in **Maple 2026**.
2. Right after `restart;`, add `currentdir(...)` pointing to the folder containing `BITSCTFfullhd.png` (using forward slashes):
   ```maple
   currentdir("D:/MAD 4472/EncryptedImage");
   ```
3. Click **Execute Entire Worksheet (`!!!`)**.
4. Wait ~10–30 seconds for Maple to process the full HD image.
5. Open the newly created `decrypted.png` to read the `BITSCTF{...}` flag.

### Option B: Command Line (PowerShell + `cmaple.exe`)
Open PowerShell in `EncryptedImage/` and run:

```powershell
& "C:\Program Files\Maple 2026\bin.X86_64_WINDOWS\cmaple.exe" -q decrypt_png.mpl
```

Maple will print:
- `Detected padding length: <L> bytes`
- `Recovered 24-byte key (decimal): [...]`
- `Success! Open 'decrypted.png' to view the BITSCTF flag.`

Open `decrypted.png` to read the flag.

---

## 5. How to Run the Local Sanity Test (Without the Official File)

To verify the Maple code works before running on the real challenge file:

```powershell
cd "d:\MAD 4472\EncryptedImage\crypto_test"
python make_test.py
& "C:\Program Files\Maple 2026\bin.X86_64_WINDOWS\cmaple.exe" -q ..\decrypt_png.mpl
```

Expected verification:
- Detected padding length matches the `Expected padding length` printed by `make_test.py`.
- Recovered key matches `[65, 66, 67, ..., 88]` (ASCII `ABCDEFGHIJKLMNOPQRSTUVWX`).
- `crypto_test/decrypted.png` opens cleanly and is byte-for-byte identical to `crypto_test/test.png`.

You can also swap `crypto_test/test.png` with any small `.png` image of your own and re-run the commands above.

---

## 6. Submission Checklist & Rubric

| Rubric Item | Weight | Where It Lives |
| --- | --- | --- |
| **Flag Value** | 60% | Paste recovered `BITSCTF{...}` into `Relevance_Statement.txt` / final PDF |
| **Maple Code** | 20% | `decrypt_png.mw` (and/or `decrypt_png.mpl`) |
| **Code Comments** | 10% | Inline step-by-step comments throughout `decrypt_png.mw` / `decrypt_png.mpl` |
| **Relevance Statement** | 10% | `Relevance_Statement.txt` (tied to Boneh–Shoup Ch. 2–5 & MAD 4472) |

Before submitting, package into a single `.zip` archive:
1. Final submission document (Flag + Relevance Statement)
2. `decrypt_png.mw` (and `decrypt_png.mpl`)
3. `BITSCTFfullhd.png` (official encrypted file)
4. `decrypted.png` (decrypted image proving the recovered flag)
