# Secure File Sharing Application

A Python-based application that enables users to securely share files with strong cryptographic protection.

## Overview

This Secure File Sharing Application provides end-to-end encryption for file sharing, ensuring that only authorized recipients can access shared files. The system combines AES (Advanced Encryption Standard) for file encryption with RSA (Rivest-Shamir-Adleman) for secure key exchange.

## Key Features

- **User Authentication**
  - Secure registration and login
  - Password hashing with salt using SHA-256
  - Protection against unauthorized access

- **Strong Encryption**
  - AES 128-bit encryption for files
  - RSA 1024-bit encryption for key exchange
  - Encrypted storage of RSA private keys

- **File Management**
  - Simple interface for sharing files
  - Easy file listing, downloading, and deletion
  - Secure metadata storage

- **Multiple Interfaces**
  - Command-Line Interface (CLI) for advanced users
  - Graphical User Interface (GUI) for ease of use

## Security Implementation

- **Password Security**: Passwords are never stored in plaintext; they are hashed with a unique salt for each user
- **Key Exchange**: AES keys are encrypted with the recipient's RSA public key
- **Private Key Protection**: RSA private keys are encrypted with the user's password
- **Secure Storage**: All files are stored in encrypted form

## How It Works

1. **File Sharing Process**:
   - Files are encrypted using AES
   - The AES key is encrypted with the recipient's RSA public key
   - Encrypted files and metadata are stored securely

2. **File Access Process**:
   - User authenticates with password
   - RSA private key is decrypted using the password
   - The AES key is decrypted using the RSA private key
   - The file is decrypted using the AES key

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-file-sharing.git
cd secure-file-sharing
```

## Usage

### Command-Line Interface

```bash
# Run the CLI version
python secure_file_sharing_cli.py
```

### Graphical User Interface

```bash
# Run the GUI version
python secure_file_sharing_gui.py
```

## System Requirements

- Python 3.6 or higher
- Required Python packages:
  - hashlib
  - os
  - uuid
  - pickle
