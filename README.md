# Encryption Lab - Cybersecurity Essentials

A Python tool for demonstrating encryption algorithms and cipher modes, showing how different modes affect pattern visibility.

## Features

- Algorithms: AES (128-bit) and DES (64-bit)
- Modes: ECB, CBC, CTR
- Visualization: Compare how different modes handle image patterns
- User-friendly: GUI interface with random key generation

## Setup

1. Navigate to project folder:
   cd encryption-lab

2. Create virtual environment:
   python3 -m venv venv

3. Activate virtual environment:
   source venv/bin/activate  (Mac/Linux)
   venv\Scripts\activate  (Windows)

4. Install dependencies:
   pip install pycryptodome matplotlib numpy pillow

5. Generate requirements file (optional):
   pip freeze > requirements.txt

## Usage

1. Run the application:
   python crypto_tool.py

2. Encrypt/Decrypt Files:
   - Select algorithm (AES/DES) and mode
   - Use generated key/IV or enter your own (hex format)
   - Select file and click Encrypt/Decrypt
   - Save the encrypted/decrypted file

3. Visualize Patterns:
   - Click "Create Test Image & Encrypt" to see ECB vulnerability
   - Or select any image file and click "Encrypt Selected Image"
   - Observe how ECB leaks patterns while CBC/CTR hide them

## Educational Value

- ECB Vulnerability: Demonstrates how identical plaintext blocks produce identical ciphertext blocks, revealing patterns
- CBC/CTR Security: Shows how chaining/streaming modes hide patterns through IV/nonce usage
- Hands-on Experience: Practical understanding of symmetric encryption concepts
- Key/IV Management: Importance of proper cryptographic parameters

## File Structure

encryption-lab/
├── venv/                 (Virtual environment)
├── crypto_tool.py        (Main application)
├── requirements.txt      (Dependencies - auto-generated)
└── README.md            (This file)

## Requirements

- Python 3.6+
- Libraries: pycryptodome, matplotlib, numpy, pillow

## Notes

- The virtual environment isolates project dependencies
- Test images are automatically created for visualization
- All keys and IVs are displayed in hex format for easy copying
- Encrypted files use .enc extension by default

## Deactivate Virtual Environment

When finished, deactivate the virtual environment:
deactivate
