#!/usr/bin/env python3

"""
User management system for the secure file sharing application.
"""

import os
import json
import time
import random
import string
from database import Database
from utils import hash_password, verify_password, generate_session_id, ensure_dir, generate_salt
from rsa import generate_keypair, save_key, load_key

class UserManager:
    def __init__(self, database=None):
        """Initialize the user manager with a database"""
        self.db = database if database else Database()
        self.active_sessions = {}  # Maps session IDs to usernames
        self.keys_dir = "./keys"
        ensure_dir(self.keys_dir)

    def register_user(self, username, password, email=None):
        """Register a new user"""
        if self.db.user_exists(username):
            return False, "Username already exists"
        
        # Hash the password with a salt
        salt = generate_salt()
        hashed_password, _ = hash_password(password, salt)
        
        # Generate RSA keypair for the user
        public_key, private_key = generate_keypair(bits=1024)
        public_key_path = os.path.join(self.keys_dir, f"{username}_public.key")
        private_key_path = os.path.join(self.keys_dir, f"{username}_private.key")
        
        # Save the public key in plaintext
        save_key(public_key, public_key_path)
        
        # Save the private key encrypted with the user's password
        save_key(private_key, private_key_path, password)
        
        # Create user data
        user_data = {
            "username": username,
            "password_hash": hashed_password,
            "salt": salt,
            "email": email,
            "created_at": time.time(),
            "last_login": None,
            "public_key_path": public_key_path,
            "private_key_path": private_key_path
        }
        
        # Save user to database
        self.db.save_user(username, user_data)
        
        return True, "User registered successfully"
    
    def authenticate(self, username, password):
        """Authenticate a user and return a session ID if successful"""
        user_data = self.db.get_user(username)
        
        if not user_data:
            return None, "User not found"
        
        if verify_password(password, user_data["password_hash"], user_data["salt"]):
            # Update last login time
            user_data["last_login"] = time.time()
            self.db.save_user(username, user_data)
            
            # Create a session
            session_id = generate_session_id()
            self.active_sessions[session_id] = username
            
            return session_id, "Authentication successful"
        
        return None, "Invalid password"
    
    def get_user_data(self, username):
        """Get user data"""
        return self.db.get_user(username)
    
    def change_password(self, username, old_password, new_password):
        """Change a user's password"""
        user_data = self.db.get_user(username)
        
        if not user_data:
            return False, "User not found"
        
        if not verify_password(old_password, user_data["password_hash"], user_data["salt"]):
            return False, "Invalid old password"
        
        # Hash the new password
        salt = generate_salt()
        hashed_password, _ = hash_password(new_password, salt)
        
        # Update the user data
        user_data["password_hash"] = hashed_password
        user_data["salt"] = salt
        self.db.save_user(username, user_data)
        
        return True, "Password changed successfully"
    
    def get_public_key(self, username):
        """Get a user's public key (no password required)"""
        user_data = self.db.get_user(username)
        
        if not user_data or "public_key_path" not in user_data:
            return None
        
        try:
            return load_key(user_data["public_key_path"])
        except Exception as e:
            print(f"Error loading public key for {username}: {e}")
            return None

    def get_private_key(self, username, password):
        """Get a user's private key (requires password to decrypt)"""
        user_data = self.db.get_user(username)
        
        if not user_data or "private_key_path" not in user_data:
            return None
        
        try:
            return load_key(user_data["private_key_path"], password)
        except Exception as e:
            print(f"Error loading private key for {username}: {e}")
            return None
    
    def validate_session(self, session_id):
        """Validate a session ID and return the associated username"""
        return self.active_sessions.get(session_id)
    
    def logout(self, session_id):
        """End a session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            return True
        return False
    
    def delete_user(self, username, password):
        """Delete a user"""
        user_data = self.db.get_user(username)
        
        if not user_data:
            return False, "User not found"
        
        if not verify_password(password, user_data["password_hash"], user_data["salt"]):
            return False, "Invalid password"
        
        # Delete RSA key files
        try:
            if "public_key_path" in user_data and os.path.exists(user_data["public_key_path"]):
                os.remove(user_data["public_key_path"])
            
            if "private_key_path" in user_data and os.path.exists(user_data["private_key_path"]):
                os.remove(user_data["private_key_path"])
        except Exception as e:
            print(f"Error deleting key files for {username}: {e}")
        
        # Remove user from database
        result = self.db.delete_user(username)
        
        # End any active sessions for this user
        for session_id, session_username in list(self.active_sessions.items()):
            if session_username == username:
                del self.active_sessions[session_id]
        
        if result:
            return True, "User deleted successfully"
        else:
            return False, "Failed to delete user"
    
    def get_all_usernames(self):
        """Get all registered usernames"""
        return self.db.get_all_users()
