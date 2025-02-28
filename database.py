#!/usr/bin/env python3

"""
A simple file-based encrypted database for the secure file sharing application.
"""

import os
import pickle
from aes import AES, encrypt as aes_encrypt, decrypt as aes_decrypt
from utils import ensure_dir, log_error, log_info

class Database:
    def __init__(self, db_dir="./database", master_key="master_key"):
        """Initialize the database with a master key for encryption"""
        self.db_dir = db_dir
        self.master_key = master_key
        ensure_dir(db_dir)
        self.users_file = os.path.join(db_dir, "users.db")
        self.messages_file = os.path.join(db_dir, "messages.db")
        self.files_file = os.path.join(db_dir, "files.db")
        
        # Initialize database files if they don't exist
        self._init_db_file(self.users_file, {})
        self._init_db_file(self.messages_file, {})
        self._init_db_file(self.files_file, {})
    
    def _init_db_file(self, filepath, default_data):
        """Initialize a database file with default data if it doesn't exist"""
        if not os.path.exists(filepath):
            self._save_data(filepath, default_data)
    
    def _encrypt_data(self, data):
        """Encrypt data before storing"""
        serialized = pickle.dumps(data)
        return aes_encrypt(self.master_key, serialized)
    
    def _decrypt_data(self, encrypted_data):
        """Decrypt data after retrieving"""
        try:
            decrypted = aes_decrypt(self.master_key, encrypted_data)
            return pickle.loads(decrypted)
        except Exception as e:
            log_error(f"Failed to decrypt data: {e}")
            return None
    
    def _save_data(self, filepath, data):
        """Save encrypted data to a file"""
        encrypted = self._encrypt_data(data)
        with open(filepath, 'wb') as f:
            f.write(encrypted)
    
    def _load_data(self, filepath):
        """Load and decrypt data from a file"""
        if not os.path.exists(filepath):
            return {}
        
        try:
            with open(filepath, 'rb') as f:
                encrypted = f.read()
            return self._decrypt_data(encrypted)
        except Exception as e:
            log_error(f"Failed to load data from {filepath}: {e}")
            return {}
    
    # User management functions
    def save_user(self, username, user_data):
        """Save or update user data"""
        users = self._load_data(self.users_file)
        users[username] = user_data
        self._save_data(self.users_file, users)
    
    def get_user(self, username):
        """Retrieve user data by username"""
        users = self._load_data(self.users_file)
        return users.get(username)
    
    def user_exists(self, username):
        """Check if a user exists"""
        users = self._load_data(self.users_file)
        return username in users
    
    def delete_user(self, username):
        """Delete a user"""
        users = self._load_data(self.users_file)
        if username in users:
            del users[username]
            self._save_data(self.users_file, users)
            return True
        return False
    
    def get_all_users(self):
        """Get all usernames"""
        users = self._load_data(self.users_file)
        return list(users.keys())
    
    # Message management functions
    def save_message(self, from_user, to_user, message_data):
        """Save a message"""
        messages = self._load_data(self.messages_file)
        
        # Initialize nested dictionaries if they don't exist
        if to_user not in messages:
            messages[to_user] = {}
        if from_user not in messages[to_user]:
            messages[to_user][from_user] = []
        
        # Append the new message
        messages[to_user][from_user].append(message_data)
        self._save_data(self.messages_file, messages)
    
    def get_messages(self, username):
        """Get all messages for a user"""
        messages = self._load_data(self.messages_file)
        return messages.get(username, {})
    
    def delete_message(self, username, from_user, message_index):
        """Delete a specific message"""
        messages = self._load_data(self.messages_file)
        
        if (username in messages and 
            from_user in messages[username] and 
            message_index < len(messages[username][from_user])):
            
            del messages[username][from_user][message_index]
            
            # Clean up empty lists and dictionaries
            if not messages[username][from_user]:
                del messages[username][from_user]
            if not messages[username]:
                del messages[username]
                
            self._save_data(self.messages_file, messages)
            return True
        
        return False
    
    # File management functions
    def save_file_metadata(self, file_id, metadata):
        """Save metadata for a shared file"""
        files = self._load_data(self.files_file)
        files[file_id] = metadata
        self._save_data(self.files_file, files)
    
    def get_file_metadata(self, file_id):
        """Get metadata for a shared file"""
        files = self._load_data(self.files_file)
        return files.get(file_id)
    
    def get_user_files(self, username):
        """Get all files shared with a specific user"""
        files = self._load_data(self.files_file)
        user_files = {}
        
        for file_id, metadata in files.items():
            if metadata['recipient'] == username:
                user_files[file_id] = metadata
        
        return user_files
    
    def delete_file_metadata(self, file_id):
        """Delete metadata for a shared file"""
        files = self._load_data(self.files_file)
        
        if file_id in files:
            del files[file_id]
            self._save_data(self.files_file, files)
            return True
        
        return False
