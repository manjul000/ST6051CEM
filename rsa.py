#!/usr/bin/env python3

"""
A simple RSA implementation for educational purposes.
This is not production-grade cryptography.
"""

import random
from aes import encrypt as aes_encrypt, decrypt as aes_decrypt
import math

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=512):
    """Generate a prime number with specified bit length"""
    while True:
        p = random.getrandbits(bits)
        # Ensure p is odd
        p |= 1
        if is_prime(p):
            return p

def gcd(a, b):
    """Euclidean algorithm for GCD"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Extended Euclidean algorithm to find modular inverse"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x
    
    gcd, x, y = extended_gcd(e, phi)
    
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % phi

def generate_keypair(bits=512):
    """Generate an RSA keypair"""
    # Generate two distinct primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    # Ensure p and q are distinct
    while p == q:
        q = generate_prime(bits)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537  # Common choice for e
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    # Compute d, the modular inverse of e mod phi
    d = mod_inverse(e, phi)
    
    # Public key is (n, e), private key is (n, d)
    return ((n, e), (n, d))

def encrypt(message, public_key):
    """Encrypt a message using RSA"""
    n, e = public_key
    
    # Convert the message to a number
    # For simplicity, we'll use a simple scheme where each character is treated separately
    encrypted = []
    for char in message:
        m = ord(char)
        c = pow(m, e, n)
        encrypted.append(c)
    
    return encrypted

def decrypt(encrypted, private_key):
    """Decrypt a message using RSA"""
    n, d = private_key
    
    decrypted = ''
    for c in encrypted:
        m = pow(c, d, n)
        decrypted += chr(m)
    
    return decrypted

def save_key(key, filename, password=None):
    """
    Save a key to a file. Encrypt private keys with AES if a password is provided.
    """
    n, e_or_d = key
    key_data = f"{n},{e_or_d}"
    
    if password:
        # Encrypt the key data using AES (for private keys)
        encrypted_data = aes_encrypt(password, key_data.encode('utf-8'))
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
    else:
        # Save the key data in plaintext (for public keys)
        with open(filename, 'w') as f:
            f.write(key_data)

def load_key(filename, password=None):
    """
    Load a key from a file. Decrypt private keys with AES if a password is provided.
    """
    try:
        if password:
            # Decrypt the key data using AES (for private keys)
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = aes_decrypt(password, encrypted_data)
            key_data = decrypted_data.decode('utf-8')
        else:
            # Load the key data in plaintext (for public keys)
            with open(filename, 'r') as f:
                key_data = f.read().strip()
        
        # Parse the key data
        n, e_or_d = map(int, key_data.split(','))
        return (n, e_or_d)
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

if __name__ == "__main__":
    # Test the RSA implementation
    public_key, private_key = generate_keypair(bits=64)  # Using smaller bits for testing
    
    # Encrypt a message
    message = "Hello, RSA!"
    encrypted = encrypt(message, public_key)
    
    # Decrypt the message
    decrypted = decrypt(encrypted, private_key)
    
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted}")
    print(f"Decrypted message: {decrypted}")
