# FileGuard

A file encryption and decryption tool built in C++17 as part of a Data Confidentiality study project. This tool demonstrates two cipher implementations — a basic XOR stream cipher and a custom Substitution-Permutation Network (SPN) inspired by the AES design.

---

## Motivation

This project was developed to understand how symmetric encryption works at a low level. Rather than using a library like OpenSSL, I implemented the cipher logic manually to get a clearer picture of what happens mathematically during encryption and decryption.

---

## Features

- XOR stream cipher with a derived key schedule
- Substitution-Permutation Network (SPN) with 10 rounds
- Secure key handling — key material is wiped from memory after use
- File existence and I/O error checking
- Simple command-line interface

---

## Project Structure

```
FileGuard/
├── include/
│   └── Encryptor.hpp
├── src/
│   ├── Encryptor.cpp
│   └── main.cpp
├── data/
│   └── input.txt
├── CMakeLists.txt
└── README.md
```

---

## Build Instructions

### Requirements
- CMake 3.16 or higher
- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)

### Steps

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

---

## Usage

```
fileguard encrypt <mode> <input_file> <output_file>
fileguard decrypt <mode> <input_file> <output_file>
```

### Modes

| Mode | Description |
|------|-------------|
| xor  | XOR stream cipher — simple and fast |
| spn  | Substitution-Permutation Network — stronger |

### Examples

```bash
# Encrypt a file using XOR
fileguard encrypt xor data/input.txt data/output.enc

# Decrypt the file
fileguard decrypt xor data/output.enc data/recovered.txt

# Encrypt using SPN
fileguard encrypt spn data/input.txt data/output.enc

# Decrypt using SPN
fileguard decrypt spn data/output.enc data/recovered.txt
```

---

## How It Works

### XOR Cipher

Each byte of the file is XOR-ed with a byte from the key schedule at position `i mod 32`.

```
Encrypt:  C = P XOR K
Decrypt:  P = C XOR K
```

XOR is its own inverse, so the encrypt and decrypt operations are identical. This is what makes it simple but also limited — a repeating key is vulnerable to frequency analysis.

### SPN Cipher

The SPN operates on 16-byte blocks and applies 10 rounds of three operations:

| Step | Purpose |
|------|---------|
| SubBytes | Non-linear S-Box substitution for confusion |
| ShiftRows | Byte permutation across the block for diffusion |
| AddRoundKey | XOR with a round-derived sub-key |

An inverse S-Box and inverse permutation table are used for decryption.

---

## Security Notes

This project is intended for educational purposes only. It should not be used to protect sensitive data in a real environment. For production use, consider AES-256-GCM via a library such as OpenSSL or libsodium, along with a proper key derivation function like Argon2id.

---

## Author

Thanapat Manasom
Computer Science — Security Project