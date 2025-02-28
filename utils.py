#!/usr/bin/env python3

"""
Utility functions for the secure file sharing application.
"""

import os
import hashlib
import base64
import time
import random
import string
from datetime import datetime

def generate_salt(length=16):
    """Generate a random salt of specified length"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def hash_password(password, salt=None):
    """Hash a password with a salt using SHA-256"""
    if salt is None:
        salt = generate_salt()
    
    # Convert to bytes if they are strings
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
        
    # Create hash
    hash_obj = hashlib.sha256(salt + password)
    hashed = hash_obj.hexdigest()
    
    return hashed, salt.decode() if isinstance(salt, bytes) else salt

def verify_password(password, stored_hash, salt):
    """Verify a password against a stored hash"""
    calculated_hash, _ = hash_password(password, salt)
    return calculated_hash == stored_hash

def generate_session_id():
    """Generate a unique session ID"""
    random_part = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    timestamp = str(int(time.time()))
    return hashlib.sha256((random_part + timestamp).encode()).hexdigest()

def bytes_to_base64(data):
    """Convert bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')

def base64_to_bytes(data):
    """Convert base64 string to bytes"""
    return base64.b64decode(data.encode('utf-8'))

def ensure_dir(directory):
    """Ensure a directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_timestamp():
    """Get current timestamp in a readable format"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sanitize_filename(filename):
    """Sanitize a filename to prevent directory traversal attacks"""
    return os.path.basename(filename)

def log_error(message):
    """Log an error message with timestamp"""
    timestamp = get_timestamp()
    print(f"[ERROR] {timestamp}: {message}")

def log_info(message):
    """Log an informational message with timestamp"""
    timestamp = get_timestamp()
    print(f"[INFO] {timestamp}: {message}")

def split_file_into_chunks(filepath, chunk_size=1024*1024):
    """Split a file into chunks of specified size"""
    chunks = []
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    return chunks

def combine_chunks_into_file(chunks, filepath):
    """Combine chunks into a file"""
    with open(filepath, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)
