#!/usr/bin/env python3

"""
Command-line interface for the secure file sharing application.
"""

import sys
from getpass import getpass
from user_management import UserManager
from file_operations import FileManager

def print_help():
    print("""
Secure File Sharing CLI

Commands:
  register <username> - Register a new user
  login <username>    - Login as a user
  send <recipient> <filepath> [message] - Send a file to another user
  list-files          - List files shared with you
  download <file_id> [output_path] - Download a shared file
  delete-file <file_id> - Delete a shared file
  logout              - Logout
  help                - Show this help message
  exit                - Exit the program
""")

def cli_main():
    user_manager = UserManager()
    file_manager = FileManager(user_manager)
    current_user = None

    print("Welcome to Secure File Sharing CLI!")
    print_help()

    while True:
        try:
            command = input("> ").strip().split()
            if not command:
                continue

            cmd = command[0].lower()
            args = command[1:]

            if cmd == "register":
                if len(args) < 1:
                    print("Usage: register <username>")
                    continue
                username = args[0]
                password = getpass("Enter password: ")
                confirm_password = getpass("Confirm password: ")
                if password != confirm_password:
                    print("Passwords do not match!")
                    continue
                success, message = user_manager.register_user(username, password)
                print(message)

            elif cmd == "login":
                if len(args) < 1:
                    print("Usage: login <username>")
                    continue
                username = args[0]
                password = getpass("Enter password: ")
                session_id, message = user_manager.authenticate(username, password)
                if session_id:
                    current_user = username
                    print(f"Logged in as {username}")
                else:
                    print(message)

            elif cmd == "send":
                if not current_user:
                    print("You must be logged in to send files")
                    continue
                if len(args) < 2:
                    print("Usage: send <recipient> <filepath> [message]")
                    continue
                recipient, filepath = args[0], args[1]
                message = " ".join(args[2:]) if len(args) > 2 else None
                success, message = file_manager.share_file(current_user, recipient, filepath, message)
                print(message)

            elif cmd == "list-files":
                if not current_user:
                    print("You must be logged in to list files")
                    continue
                files = file_manager.get_shared_files(current_user)
                if not files:
                    print("No files shared with you.")
                else:
                    print("Files shared with you:")
                    for file_id, metadata in files.items():
                        print(f"ID: {file_id}, Filename: {metadata['filename']}, Sender: {metadata['sender']}, Message: {metadata.get('message', 'No message')}")

            elif cmd == "download":
                if not current_user:
                    print("You must be logged in to download files")
                    continue
                if len(args) < 1:
                    print("Usage: download <file_id> [output_path]")
                    continue
                file_id = args[0]
                output_path = args[1] if len(args) > 1 else None
                password = getpass("Enter your password to decrypt the file: ")
                success, message = file_manager.download_file(current_user, file_id, output_path, password)
                if success:
                    print(f"File downloaded to {message}")
                else:
                    print(message)

            elif cmd == "delete-file":
                if not current_user:
                    print("You must be logged in to delete files")
                    continue
                if len(args) < 1:
                    print("Usage: delete-file <file_id>")
                    continue
                file_id = args[0]
                success, message = file_manager.delete_shared_file(current_user, file_id)
                print(message)

            elif cmd == "logout":
                if not current_user:
                    print("You are not logged in")
                    continue
                current_user = None
                print("Logged out")

            elif cmd == "help":
                print_help()

            elif cmd == "exit":
                print("Goodbye!")
                break

            else:
                print("Unknown command. Type 'help' for a list of commands.")

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    cli_main()