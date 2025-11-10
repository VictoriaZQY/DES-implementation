# DES Tool (FIPS 46-3)

## Overview
DES is a symmetric-key block cipher standardized in FIPS PUB 46-3 with a block size of 64 bits and 16 rounds of Feistel structure. DES remains a canonical algorithm for teaching cryptography, despite its short key size (56 effective bits) and practical obsolescence for modern security applications. 

This project implements both encryption and decryption parts of DES according to the FIPS specification and builds a PyQt5-based GUI demonstrating text and file modes, as required by the project description. The goal of this project is to:
* Implement both DES encryption and decryption for arbitrary-length plaintext/ciphertext (i.e., by processing in 64-bit blocks and padding as required).
* Provide a user-friendly interface allowing users to supply plaintext/ciphertext via text input or file system selection.
* Ensure encryption and decryption are independent operations (each invoked with an explicit key).
* Include robustness measures (error handling, informative messages, and file-mode workflows including compression/decompression where applicable).
---


## Quick start

### Prerequisites

* Python 3.x
* PyQt5==5.15.11 
* PyQt5_sip==12.15.0

### GUI Introduction
The main window opens with:
* Top-left (3): key input box and a short hint underneath.
* Top-right (2): large Select File button and filename display.
* Middle-left (1): Input text area with Copy and Clear buttons.
* Middle-right (7): Output area (read-only) with Copy and Clear buttons.
* Bottom (4), (5) & (6): Encrypt (5) and Decrypt (6) buttons, and a status label
<img width="700" height="595" alt="guide" src="https://github.com/user-attachments/assets/2fc0924f-b3bc-4307-a3c7-6d42da720779" />

### Run GUI

```bash
python main.py
```

### Text mode encryption/decryption
1. Type (or paste) plaintext into the **Input** box (1).
2. Enter an 8-character key (or any string and the program will pad/truncate to 8 bytes) in
the **Key** input area (3). The tip is the format hint for users.
3. The status (4) is ready, meaning the program is ready to compile.
4. Click **Encrypt** (5): The app will perform block-by-block DES encryption and show the ciphertext in the Output area (7). Note that for text-mode encryption, output may contain non-printable characters and the app prints them as-is.
<img width="700" height="560" alt="result_e" src="https://github.com/user-attachments/assets/14e536bb-a444-4ceb-aaa2-06a05739b0de" />

5. To reverse, copy the ciphertext back to the Input area (1). You can use the **Copy** button to copy content or use the **Clear** button to clear the area. Please make sure the same key is entered, and click **Decrypt** (6). The **Output** (7) will show plaintext
<img width="700" height="560" alt="result_d" src="https://github.com/user-attachments/assets/3dd5de36-d582-4e62-913f-f521401dd4ea" />

### File mode encryption/decryption
1. Click the large **Select File** button (2) and choose a file from disk. The filename will display under the button and in the **Input** area (1)
2. Enter a key (3).
3. Click Encrypt (5):
  * The tool will compress the selected file into a ZIP archive and then encrypt the ZIP bytes block-by-block. The encrypted bytes are written to disk as encrypted <basename>.zip.
  * A non-modal dialog informs the user that saving has completed, and the app may auto-close after a short delay.
4. For decryption:
  * Click Select File (2) and pick the encrypted file (the one produced by the program).
  * Enter the same key used to encrypt in the key input area (3).
  * Click Decrypt (6): the app will decrypt bytes, write them to a temporary zip file decrypted <basename>.zip, and then extract its contents to the directory.
<img width="700" height="560" alt="file_upload" src="https://github.com/user-attachments/assets/ac66900e-f2e4-4eac-b2c7-398debd5e6e1" />

### Tips
  * Use the Copy button on the input area to copy input or the one on the output area to copy output. The status will be reflected on the status label.
<img width="700" height="560" alt="copy" src="https://github.com/user-attachments/assets/04ab9599-8402-4f86-ac26-2fd3f8d17867" />
<img width="700" height="560" alt="copy_o" src="https://github.com/user-attachments/assets/852aa689-0df3-428f-9978-21873d7ad152" />

  * Use the Clear button on the input area to clear input and reset the selected file state (this returns the UI to the initial **Ready** state).
  * The separation bar can be moved if one area needs to use more space. ![move](https://github.com/user-attachments/assets/d9fe8384-9dd6-476b-b4fb-dc80fc347e2e)

  * Always use the same key for encryption and decryption.

---

## Problems Encountered and Solutions

### Empty Key Entered
* Problem: User clicks the Encrypt button (5) or Decrypt button (6) without entering the key in the key area (3).
* Solution: The system will pop up an alert to the user to inform them. The user can continue after clicking **OK**.
<img width="700" height="595" alt="no_key" src="https://github.com/user-attachments/assets/6c74a5a1-a4d7-4991-9200-12f1e3a00642" />

### Empty Text Entered
* Problem: User clicks the Encrypt button (5) or Decrypt button (6) without entering the plain text in the input area (1) or selecting a file (2).
* Solution: The system will pop up an alert to the user to inform them. The user can continue after clicking **OK**.
<img width="700" height="594" alt="no_text1" src="https://github.com/user-attachments/assets/3c705d57-ecab-4658-9fb2-d0429ecaf38e" />
---
