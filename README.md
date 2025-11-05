# DES Tool (FIPS 46-3)

## Overview

This project contains a Python implementation of the Data Encryption Standard (DES) following FIPS PUB 46-3. It provides:

* A DES core implementation (initial/final permutations, expansion, S-boxes, P-permutation, PC-1/PC-2, key schedule and 16 Feistel rounds).
* Support for arbitrary-length plaintext via PKCS#7 padding.
* ECM and CBC modes of operation (ECB, CBC).
* A deterministic KDF that accepts *any-length* user key material and derives an 8-byte DES key (SHA-256 → first 8 bytes → set odd parity per byte).
* A simple Tkinter GUI for interactive use and a minimal CLI mode for the canonical test vector.
---

## Features

* Full DES implementation per FIPS 46-3.
* Arbitrary plaintext length: PKCS#7 padding used.
* Arbitrary key length: deterministic KDF (SHA-256-based) produces a valid 64-bit DES key with odd parity.
* ECB and CBC modes supported.
* GUI for file/text input and encrypt/decrypt operations.
* CLI `--nogui` test that runs the canonical DES example:

  * Plaintext: `0123456789ABCDEF`
  * Key: `133457799BBCDFF1`
  * Expected ciphertext: `85E813540F0AB405`

---

## Quick start

### Prerequisites

* Python 3.x
* PyQt5==5.15.11 
* PyQt5_sip==12.15.0


### Run GUI

```bash
python main.py
```

* Enter a key (any length).
* Choose `ECB` or `CBC`.
* Paste or load plaintext via **Load file**.
* Click **Encrypt**. The result (hex) appears in the text box. For CBC, an IV is generated and shown.
* To decrypt, paste the ciphertext (and IV for CBC — see *format notes* below) and click **Decrypt**.

### Run canonical test (CLI)

```bash
python des_tool.py --nogui
```

This prints the single-block canonical test used for verification.

---

## Input / Output formats & GUI notes

* The GUI displays ciphertext as hex text (not raw binary). When saving with the GUI **Save output...** button, it saves the *text shown* (UTF-8), not the raw binary. (See known issues below and recommended fixes.)
* For CBC the GUI displays IV hex and ciphertext hex. The decrypt code expects raw hex (IV then ciphertext) or concatenated hex; the GUI's labeled format is not machine-parsed automatically — remove labels or use the combined hex string when decrypting. (See recommended fix for a better usable data format.)

---

## Key handling

* Any-length user key → `derive_key_from_bytes(bytes)`:

  1. `SHA-256` over user key bytes
  2. Take first 8 bytes
  3. Set **odd parity** in each byte (LSB used as parity bit, set so each full byte has odd number of 1 bits)
* If a precise 8-byte key (with parity) is required, the CLI test uses `generate_subkeys` directly with that 8-byte key.

---

## Tests you should run in the demo

1. **Canonical DES single block:**

   * Use CLI `--nogui` and verify ciphertext equals `85E813540F0AB405`.
2. **Roundtrip tests**:

   * Encrypt a text file (multi-KB) with a short key (e.g., "abc"), decrypt it, and verify exact match.
   * Repeat with a long key (e.g., a 256-byte key) to show arbitrary key handling.
   * Try CBC and ECB modes.
3. **Invalid input handling**:

   * Feed random binary data into GUI (it will show hex) and verify decryptability.
4. **Padding edge cases**:

   * Empty input, input with length exactly a multiple of 8, etc.

---

## Known limitations & recommended improvements

* The GUI's **display** and the **decryption parser** are not well aligned. The GUI prints:

  ```
  IV (hex):
  <iv hex>

  Ciphertext (hex):
  <cipher hex>
  ```

  but the decrypt parser expects raw hex or the IV on the first line (no labels). This is confusing — see "Fixes" below.
* `Save output...` saves the textual display (UTF-8), not the raw binary ciphertext. Add explicit Save Binary button.
* For security/production, prefer AES or at least 3DES. Single DES is insecure against brute-force attacks.
* No MAC/authentication is provided (CBC lacks integrity). Add HMAC or an authenticated mode if you need authenticity.
* No streaming for very large files (the GUI loads files into memory). For large files, implement block streaming to reduce memory use.
* The Tkinter UI is intentionally lightweight. Consider a clearer file formats workflow (separate file pickers for input and output) or a small web UI.

---

## Implementation notes (developer)

* All major permutation and S-box tables are hard coded per FIPS 46-3.
* The code sets odd parity on derived keys to comply with FIPS parity requirement.
* The key derivation method is deterministic and simple (SHA-256 → first 8 bytes). If you want to preserve a user-provided exact 8-byte key, add a "Use raw key (hex)" option in the GUI.
* The canonical test uses the raw 8-byte key directly (not the KDF) to match the standard vector.

---

## Security notice

* **DES is deprecated.** Do not use single DES to protect real sensitive data.
* The KDF is deterministic and does not add salt; this is fine for demo/assignment but not recommended for production key derivation.
* CBC mode without authentication is vulnerable to active modifications. Consider using an AEAD mode (e.g., AES-GCM) or include HMAC.

---

# Code analysis (detailed)

Below I analyze the script you provided: strengths, correctness, probable bugs, edge cases, and recommended fixes.

---

## 1) Correctness vs FIPS 46-3

* **Permutations / S-boxes / shift schedule / PC1/PC2**: Implemented exactly (tables appear correct).
* **Initial/Final permutation and round structure**: The implementation follows the standard Feistel structure: `L_{i+1} = R_i; R_{i+1} = L_i xor f(R_i, K_i)`. The decryption routine iterates keys in reverse, using the same f-function — correct approach.
* **S-box indexing and bit ordering**: The code expands 32→48 bits with the E table, then extracts 6-bit chunks and computes `(bit0<<1|bit5)` for row and bits 1–4 for column. This matches canonical DES bit numbering (with the code's byte-to-bit mapping consistent across permutations). The implementation produced the expected S-box index patterns in the earlier debug runs.
* **Parity**: The code forces odd parity on derived keys. This matches FIPS parity requirement.

**Conclusion:** The core DES logic is implemented correctly for the provided tables and bit ordering. The CLI canonical test path uses `generate_subkeys` directly with the 8-byte key (so it can be validated against the FIPS vector). That is good.

---

## 2) KDF & key handling: design tradeoffs and caveats

* **Design choice:** Accept any-length keys by deterministically deriving an 8-byte DES key via `SHA-256(user_key)[:8]`, then forcing parity. This meets the assignment requirement *"no restriction on key length"* and ensures proper parity.
* **Caveat:** Users sometimes expect that entering exactly 16 hex characters (an 8-byte key) will be used as-is; the current GUI always applies the hash/KDF path. The CLI test uses the raw 8-byte path (so canonical test works). I recommend adding a GUI checkbox *"Use raw key (hex)"* and a parsing path: if enabled and the key entry is valid 16-hex-digit string, use those bytes directly (after optionally checking parity) instead of hashing.

---

## 3) Padding & modes

* PKCS#7 padding for blocksize 8 is implemented and correctly validated/unpadded. The code raises an exception if padding is invalid — good for detecting wrong key or corrupt ciphertext.
* CBC mode: encryption uses IV that can be provided or random; decryption accepts IV too. But **GUI IV handling is inconsistent** (see bugs below).
* ECB mode: supported and straightforward.

---

## 4) GUI behavior — bugs and UX issues

These are the main items to fix:

### Problem A — GUI encrypt output format vs decryption parser

* `do_encrypt()` writes a **labelled** display:

  ```
  IV (hex):
  <iv hex>

  Ciphertext (hex):
  <ct hex>
  ```
* `do_decrypt()` expects either:

  * lines[0] is raw IV hex and lines[1] ciphertext hex; **or**
  * a single concatenated hex string with IV first 16 hex chars then ciphertext
* Because the GUI includes the label text, `do_decrypt()` will *not* parse the GUI's own output. That means copy-paste from the GUI's encrypt result to the GUI decrypt box will typically fail.

**Fix suggestions:**

* Change GUI to produce a machine-friendly, unambiguous output when encryption is performed. For example:

  * Option 1: Show a single combined hex string: `<IV_HEX><CIPHERTEXT_HEX>` (so decrypt can just split first 16 hex characters).
  * Option 2: Provide two dedicated text fields: one for IV hex and one for ciphertext hex with separate copy buttons.
  * Option 3: Add a `Save binary (iv+ct)` button that writes the raw bytes `[IV||CIPHERTEXT]` to file and a `Load` button that can read that format.
* Also update `do_decrypt()` to accept the GUI labelled format by stripping labels and non-hex text (or searching for 16-hex substring).

### Problem B — Save output writes textual display, not raw binary

* The `save_output()` call in the GUI saves the textual contents of the text box as UTF-8. For binary ciphertext you often want raw bytes written.
* **Fix:** Add a separate Save Binary button that writes raw bytes (IV + ciphertext) or a checkbox to choose raw/binary vs textual hex output. Provide both options in the GUI.

### Problem C — Loading files and automatic display

* `load_file()` tries `data.decode('utf-8')` and otherwise writes the file hex. The UI then places that into the same text box used for hex and plaintext input. This can be confusing.
* **Fix:** Provide an explicit "Load as raw" or "Load as text" option so users know what's being loaded.

---

## 5) Error handling & robustness

* `pkcs7_unpad` raises `ValueError` on invalid padding — good. GUI shows this as a messagebox error on decryption failure.
* The GUI attempts `txt_content.encode('utf-8')` inside `do_encrypt()`; that will always succeed because `txt_content` is a Python string; the `except` branch is unreachable. But the code attempts to handle binary vs hex text; better approach: detect whether the user input is hex (if it only contains hex chars and whitespace) vs text and convert appropriately.
* `des_decrypt()` expects ciphertext length multiple of 8; if user provides non-multiple-of-8 hex, the code might produce partial last block or raise when unpadding. Add a check and user-friendly error if length % 8 != 0.

---

## 6) Performance & memory

* Implementation uses pure Python bit operations: fine for teaching and demo but not optimized for large data volumes. Using `bytearray` operations and block-wise processing is fine but not high throughput.
* GUI reads entire files into memory — for large files implement streaming (read N blocks and encrypt/write progressively) to reduce memory footprint.

---

## 7) Security notes

* DES is **broken** for modern security. Brute force is trivial for well-resourced attackers. Use AES-GCM / AES-CBC+HMAC or 3DES where policy demands legacy compatibility.
* The KDF uses SHA-256 (no salt). This is deterministic. For producing encryption keys from passwords, prefer industry-standard KDFs like PBKDF2 / scrypt / Argon2 with a salt + iteration parameter.
* CBC provides confidentiality but no integrity. Add authentication (HMAC) or use AEAD mode.

---

## 8) Suggested code changes & small patches

### A. Make GUI produce machine-friendly output and support raw key option

Replace `do_encrypt()` display with something like:

```python
# on encrypt (CBC)
iv = urandom(8)
ct, _ = des_encrypt(data, key_mat, mode='CBC', iv=iv)
# machine-friendly single-line combined hex:
combined = iv.hex().upper() + ct.hex().upper()
# also show separate fields for IV and CT if desired
txt.delete('1.0', END)
txt.insert(END, combined)
```

And in `do_decrypt()` accept combined hex by splitting first 16 hex chars:

```python
rawhex = raw.replace('\n','').replace(' ','')
if mode == 'CBC':
    iv = bytes.fromhex(rawhex[:16])
    ct = bytes.fromhex(rawhex[16:])
```

### B. Add "Use raw key (hex)" checkbox

* If key entry looks like 16 hex digits and the checkbox is ticked, interpret key as raw 8 bytes:

```python
if use_raw_key and re.fullmatch(r'[0-9A-Fa-f]{16}', key_text):
    key_bytes = bytes.fromhex(key_text)
else:
    key_bytes = key_text.encode('utf-8')
```

### C. Save binary button

* Implement `save_binary(iv, ct)` that writes raw bytes to file.

### D. Improve error messages & input detection

* Before decrypting verify ciphertext length is multiple of 16 hex chars (8 bytes).
* Detect whether input is hex automatically and show a user-facing hint.

---

## 9) Unit testing & validation

Add `tests/test_des_vectors.py` with:

* Canonical FIPS single block vector.
* A few additional known vectors from DES test suites.
* Roundtrip tests random plaintexts and random keys (multiple sizes) verifying decrypt(encrypt(pt)) == pt.
* Edge cases: zero-length message, multiple-of-8 length messages.

You can add a small test harness that uses Python's `unittest` or `pytest`.

Example test:

```python
def test_canonical():
    pt = bytes.fromhex("0123456789ABCDEF")
    key = bytes.fromhex("133457799BBCDFF1")
    subkeys = generate_subkeys(key)
    ct = des_encrypt_block(pt, subkeys)
    assert ct.hex().upper() == "85E813540F0AB405"
```

---

## 10) Roadmap (suggested)

* Fix GUI parsing and save bugs.
* Add "Use raw hex key" option.
* Add streaming file encrypt/decrypt.
* Add unit tests and CI (GitHub Actions).
* (Optional) Add 3DES support and/or AES implementation for comparison.
* Add HMAC/AEAD mode for authenticated encryption.

---