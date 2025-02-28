#!/usr/bin/env python3

"""
File operations for the secure file sharing application.
"""

import os
import uuid
import time
from aes import AES, encrypt as aes_encrypt, decrypt as aes_decrypt
from rsa import encrypt as rsa_encrypt, decrypt as rsa_decrypt
from database import Database
from utils import ensure_dir, bytes_to_base64, base64_to_bytes, log_error, log_info, sanitize_filename

class FileManager:
    def __init__(self, user_manager, database=None):
        """Initialize the file manager"""
        self.user_manager = user_manager
        self.db = database if database else Database()
        self.files_dir = "./shared_files"
        ensure_dir(self.files_dir)
    
    def share_file(self, sender_username, recipient_username, filepath, message=None):
        """Share a file from one user to another"""
        # Check if both users exist
        sender_data = self.user_manager.get_user_data(sender_username)
        recipient_data = self.user_manager.get_user_data(recipient_username)

        if not sender_data or not recipient_data:
            return False, "Sender or recipient not found"

        # Generate a random password for AES encryption
        aes_password = str(uuid.uuid4())

        # Get the recipient's public key (no password required)
        recipient_public_key = self.user_manager.get_public_key(recipient_username)

        if not recipient_public_key:
            return False, "Could not load recipient's public key"

        # Encrypt the AES password with the recipient's public key
        encrypted_password = rsa_encrypt(aes_password, recipient_public_key)

        try:
            # Read and encrypt the file
            with open(filepath, 'rb') as f:
                file_data = f.read()

            encrypted_file_data = aes_encrypt(aes_password, file_data)

            # Generate a unique file ID
            file_id = str(uuid.uuid4())

            # Determine the filename (without path)
            filename = os.path.basename(filepath)

            # Save the encrypted file
            encrypted_file_path = os.path.join(self.files_dir, file_id)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_file_data)

            # Create file metadata
            metadata = {
                "file_id": file_id,
                "filename": filename,
                "sender": sender_username,
                "recipient": recipient_username,
                "encrypted_password": encrypted_password,
                "encrypted_file_path": encrypted_file_path,
                "message": message,
                "timestamp": time.time(),
                "status": "unread",
                "file_size": len(file_data)
            }

            # Save file metadata to database
            self.db.save_file_metadata(file_id, metadata)

            return True, "File shared successfully"

        except Exception as e:
            log_error(f"Failed to share file: {e}")
            return False, f"Failed to share file: {str(e)}"
    
    def get_shared_files(self, username):
        """Get files shared with a user"""
        return self.db.get_user_files(username)
    
    def get_file_info(self, file_id):
        """Get information about a shared file"""
        return self.db.get_file_metadata(file_id)
    
    def download_file(self, username, file_id, output_path=None, password=None):
        """Download and decrypt a file"""
        # Get file metadata
        metadata = self.db.get_file_metadata(file_id)
        
        if not metadata or metadata["recipient"] != username:
            return False, "File not found or not shared with you"
        
        try:
            # Get the encrypted password
            encrypted_password = metadata["encrypted_password"]
            
            # Get the user's private key (requires password)
            private_key = self.user_manager.get_private_key(username, password)
            
            if not private_key:
                return False, "Could not load your private key"
            
            # Decrypt the AES password
            aes_password = rsa_decrypt(encrypted_password, private_key)
            
            # Read the encrypted file
            with open(metadata["encrypted_file_path"], 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the file
            decrypted_data = aes_decrypt(aes_password, encrypted_data)
            
            # Determine output path
            if not output_path:
                output_dir = f"./downloads/{username}"
                ensure_dir(output_dir)
                output_path = os.path.join(output_dir, sanitize_filename(metadata["filename"]))
            
            # Write the decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update file status
            metadata["status"] = "read"
            self.db.save_file_metadata(file_id, metadata)
            
            return True, output_path
            
        except Exception as e:
            log_error(f"Failed to download file: {e}")
            return False, f"Failed to download file: {str(e)}"
    
    def delete_shared_file(self, username, file_id):
        """Delete a shared file"""
        # Get file metadata
        metadata = self.db.get_file_metadata(file_id)
        
        if not metadata:
            return False, "File not found"
        
        # Check if the user is the sender or recipient
        if metadata["sender"] != username and metadata["recipient"] != username:
            return False, "You don't have permission to delete this file"
        
        try:
            # Delete the encrypted file
            if os.path.exists(metadata["encrypted_file_path"]):
                os.remove(metadata["encrypted_file_path"])
            
            # Delete the metadata
            result = self.db.delete_file_metadata(file_id)
            
            if result:
                return True, "File deleted successfully"
            else:
                return False, "Failed to delete file metadata"
                
        except Exception as e:
            log_error(f"Failed to delete file: {e}")
            return False, f"Failed to delete file: {str(e)}"
