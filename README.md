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
├── Relevance_Statement.txt    # Final submission Flag + Relevance Statement
├── enc27-1-1.py               # Original encryption algorithm provided in the prompt
├── BITSCTFfullhd-1-1.png      # Original downloaded Canvas encrypted PNG
├── BITSCTFfullhd.png          # Copy of BITSCTFfullhd-1-1.png (input filename expected by Maple)
├── decrypt_png.mpl            # Commented Maple script (CLI-ready)
├── decrypt_png.mw             # Commented Maple worksheet (Maple Desktop GUI)
├── decrypted.png              # Recovered original PNG showing the flag
└── testing/                   # Self-contained local test environment
    ├── make_test.py           # Encrypts test.png -> BITSCTFfullhd.png with a known key
    ├── test.png               # Sample PNG input
    ├── BITSCTFfullhd.png      # Encrypted test PNG
    └── decrypted.png          # Decrypted test output (matches test.png)
```

---

## 4. Recovered Results (Official File)

Running `decrypt_png.mpl` on the official `BITSCTFfullhd-1-1.png` (copied to `BITSCTFfullhd.png`, 44,904 bytes):

- **Detected padding length:** `19` bytes (original PNG size: `44,885` bytes)
- **Recovered 24-byte key (decimal):** `[114, 107, 104, 37, 81, 80, 52, 103, 48, 38, 51, 103, 52, 54, 64, 52, 42, 37, 102, 40, 85, 78, 35, 92]`
- **Recovered 24-byte key (ASCII):** ``rkh%QP4g0&3g46@4*%f(UN#\``
- **Decrypted image:** `decrypted.png` (1920 × 1080 PNG)
- **Flag:** `BITSCTF{p_en_gee}`

---

## 5. How to Re-Run the Decryption

Make sure `BITSCTFfullhd.png` is in the root folder (`EncryptedImage/`). (If you only have `BITSCTFfullhd-1-1.png`, copy or rename it to `BITSCTFfullhd.png`.)

### Option A: Maple Desktop GUI (`decrypt_png.mw`)
1. Open `decrypt_png.mw` in **Maple 2026**.
2. Right after `restart;`, add `currentdir(...)` pointing to the folder containing `BITSCTFfullhd.png` (using forward slashes):
   ```maple
   currentdir("D:/MAD 4472/EncryptedImage");        # Windows
   currentdir("/Users/<you>/EncryptedImage");       # macOS
   ```
3. Click **Execute Entire Worksheet (`!!!`)**.
4. Open `decrypted.png` to view the `BITSCTF{p_en_gee}` flag.

### Option B: Windows Command Line (PowerShell + `cmaple.exe`)
Open PowerShell in `EncryptedImage/` and run:

```powershell
& "C:\Program Files\Maple 2026\bin.X86_64_WINDOWS\cmaple.exe" -q decrypt_png.mpl
```

### Option C: macOS Command Line (Terminal + `maple`)
Open Terminal, `cd` into the `EncryptedImage/` folder, and run:

```bash
"/Library/Frameworks/Maple.framework/Versions/2026/bin/maple" -q decrypt_png.mpl
open decrypted.png
```

For either command-line option, Maple will print:
- `Detected padding length: 19 bytes`
- `Recovered 24-byte key (decimal): [114, 107, 104, 37, 81, 80, 52, 103, 48, 38, 51, 103, 52, 54, 64, 52, 42, 37, 102, 40, 85, 78, 35, 92]`
- `Success! Open 'decrypted.png' to view the BITSCTF flag.`

---

## 6. How to Run the Local Sanity Test

To verify the Maple script on a custom PNG with a known key (`ABCDEFGHIJKLMNOPQRSTUVWX`):

**Windows (PowerShell):**

```powershell
cd "d:\MAD 4472\EncryptedImage\testing"
python make_test.py
& "C:\Program Files\Maple 2026\bin.X86_64_WINDOWS\cmaple.exe" -q ..\decrypt_png.mpl
```

**macOS (Terminal), starting in `EncryptedImage/`:**

```bash
cd testing
python3 make_test.py
"/Library/Frameworks/Maple.framework/Versions/2026/bin/maple" -q ../decrypt_png.mpl
cmp decrypted.png test.png && echo "Match"
```

Expected verification:
- Detected padding length matches the `Expected padding length` printed by `make_test.py`.
- Recovered key matches `[65, 66, 67, ..., 88]` (ASCII `ABCDEFGHIJKLMNOPQRSTUVWX`).
- `testing/decrypted.png` opens cleanly and is byte-for-byte identical to `testing/test.png`.

---

## 7. Submission Checklist & Rubric

| Rubric Item | Weight | Where It Lives |
| --- | --- | --- |
| **Flag Value** | 60% | `BITSCTF{p_en_gee}` in `Relevance_Statement.txt` |
| **Maple Code** | 20% | `decrypt_png.mw` and `decrypt_png.mpl` |
| **Code Comments** | 10% | Inline step-by-step comments throughout `decrypt_png.mw` / `decrypt_png.mpl` |
| **Relevance Statement** | 10% | `Relevance_Statement.txt` (tied to Boneh–Shoup Ch. 2–5 & MAD 4472) |

Included in `MAD4472_EncryptedImage_Submission.zip`:
1. `Relevance_Statement.txt` (Flag + Relevance Statement)
2. `decrypt_png.mw` and `decrypt_png.mpl` (Commented Maple code)
3. `BITSCTFfullhd.png` (Encrypted PNG input)
4. `decrypted.png` (Decrypted PNG showing `BITSCTF{p_en_gee}`)
5. `enc27-1-1.py` and `README.md`
