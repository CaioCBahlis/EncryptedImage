# ==============================================================================
# Project: Known-Plaintext Attack on a 24-Byte Repeating-Key XOR Cipher
# Input:   BITSCTFfullhd.png (encrypted PNG with PKCS#7-style 24-byte padding)
# Output:  decrypted.png (recovered original PNG containing the BITSCTF flag)
# ==============================================================================

restart;
with(Bits): # Provides bitwise Xor() for byte-level key recovery and decryption

# ------------------------------------------------------------------------------
# Step 1: Load the encrypted file and convert bytes to unsigned integers (0..255)
# ------------------------------------------------------------------------------
# FileTools:-Binary:-ReadFile returns signed 8-bit integers (-128..127).
# Taking each byte 'mod 256' converts it to the standard unsigned range (0..255).
ct_raw := FileTools:-Binary:-ReadFile("BITSCTFfullhd.png"):
n := numelems(ct_raw):
ct := Array(1..n, i -> ct_raw[i] mod 256):

# Verify that the ciphertext length is a multiple of 24 as guaranteed by add_pad
if (n mod 24) <> 0 then
    error "Ciphertext length (%1) is not a multiple of 24.", n:
end if:

# ------------------------------------------------------------------------------
# Step 2: Recover key[1..16] using the known 16-byte PNG header
# ------------------------------------------------------------------------------
# Every valid PNG starts with an 8-byte signature followed by the 8-byte IHDR
# chunk length and type (given in hex: 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52)
png_header := [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]:

# Since C = P xor K, XORing ciphertext with known plaintext recovers the key: K = C xor P
key := Array(1..24, datatype = integer):
for i from 1 to 16 do
    key[i] := Xor(ct[i], png_header[i]):
end do:

# ------------------------------------------------------------------------------
# Step 3: Recover key[17..24] using the PNG IEND chunk and padding structure
# ------------------------------------------------------------------------------
# Every valid PNG ends with the fixed 12-byte IEND chunk:
# Hex: 00 00 00 00 49 45 4E 44 AE 42 60 82
png_iend := [0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130]:

# The encryption script appends L bytes of value L (where 1 <= L <= 24) so the
# total length is a multiple of 24. We test each candidate L against key[1..16].
pad_len := 0:

for L from 1 to 24 do
    # Expected end of the padded plaintext: IEND chunk + L copies of byte L
    tail := [op(png_iend), seq(L, j = 1..L)]:
    tlen := nops(tail):
    start_idx := n - tlen:
    valid := true:

    # Check every byte of 'tail' that aligns with the already-known key[1..16]
    for j from 1 to tlen do
        pos := start_idx + j:
        kidx := ((pos - 1) mod 24) + 1:
        if kidx <= 16 then
            if Xor(ct[pos], tail[j]) <> key[kidx] then
                valid := false:
                break:
            end if:
        end if:
    end do:

    # Once all overlapping positions match, L is confirmed. Because n is a
    # multiple of 24, the final 8 bytes of the file always align with key[17..24].
    if valid then
        pad_len := L:
        for k from 1 to 8 do
            key[16 + k] := Xor(ct[n - 8 + k], tail[tlen - 8 + k]):
        end do:
        break:
    end if:
end do:

if pad_len = 0 then
    error "Could not determine valid padding length or IEND alignment.":
end if:

printf("Detected padding length: %d bytes\n", pad_len);
printf("Recovered 24-byte key (decimal): %a\n", convert(key, list));

# ------------------------------------------------------------------------------
# Step 4: Decrypt the full file, remove padding, and export decrypted.png
# ------------------------------------------------------------------------------
pt_len := n - pad_len:
pt_signed := Array(1..pt_len, datatype = integer[1]):

for i from 1 to pt_len do
    kidx := ((i - 1) mod 24) + 1:
    val := Xor(ct[i], key[kidx]):
    # Convert unsigned byte (0..255) back to signed integer[1] (-128..127)
    if val >= 128 then
        pt_signed[i] := val - 256:
    else
        pt_signed[i] := val:
    end if:
end do:

FileTools:-Binary:-WriteFile("decrypted.png", pt_signed):
printf("Success! Open 'decrypted.png' to view the BITSCTF flag.\n");
