#!/usr/bin/env python3

"""
Graphical user interface for the secure file sharing application.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from user_management import UserManager
from file_operations import FileManager

class SecureFileSharingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Sharing")
        self.root.geometry("900x900")  # Set initial window size
        self.root.minsize(600, 400)  # Set minimum window size
        self.root.configure(bg="#333333")  # Dark gray background

        self.user_manager = UserManager()
        self.file_manager = FileManager(self.user_manager)
        self.current_user = None

        self.setup_ui()

    def setup_ui(self):
        # Configure grid weights for resizing
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Login Frame
        self.login_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        self.login_frame.grid(row=0, column=0, sticky="nsew")

        # Center the login frame content
        self.login_frame.grid_rowconfigure(0, weight=1)
        self.login_frame.grid_rowconfigure(4, weight=1)
        self.login_frame.grid_columnconfigure(0, weight=1)
        self.login_frame.grid_columnconfigure(2, weight=1)

        ttk.Label(self.login_frame, text="Username:", style="TLabel").grid(row=1, column=1, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(self.login_frame, width=30, font=("Arial", 12))
        self.username_entry.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        ttk.Label(self.login_frame, text="Password:", style="TLabel").grid(row=2, column=1, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=30, font=("Arial", 12))
        self.password_entry.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        ttk.Button(self.login_frame, text="Login", command=self.login, style="Accent.TButton").grid(row=3, column=1, columnspan=2, pady=10)
        ttk.Button(self.login_frame, text="Register", command=self.register, style="TButton").grid(row=4, column=1, columnspan=2, pady=10)

        # Main Frame
        self.main_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        # Center the main frame content
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(8, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(self.main_frame, text="Recipient:", style="TLabel").grid(row=1, column=1, padx=5, pady=5, sticky="e")
        self.recipient_entry = ttk.Entry(self.main_frame, width=30, font=("Arial", 12))
        self.recipient_entry.grid(row=1, column=2, padx=5, pady=5, sticky="w")

        ttk.Label(self.main_frame, text="File:", style="TLabel").grid(row=2, column=1, padx=5, pady=5, sticky="e")
        self.file_entry = ttk.Entry(self.main_frame, width=30, font=("Arial", 12))
        self.file_entry.grid(row=2, column=2, padx=5, pady=5, sticky="w")
        ttk.Button(self.main_frame, text="Browse", command=self.browse_file, style="TButton").grid(row=2, column=3, padx=5, pady=5)

        ttk.Label(self.main_frame, text="Message:", style="TLabel").grid(row=3, column=1, padx=5, pady=5, sticky="e")
        self.message_entry = ttk.Entry(self.main_frame, width=30, font=("Arial", 12))
        self.message_entry.grid(row=3, column=2, padx=5, pady=5, sticky="w")

        ttk.Button(self.main_frame, text="Send File", command=self.send_file, style="Accent.TButton").grid(row=4, column=1, columnspan=3, pady=10)

        # File Listbox with Scrollbar
        self.file_listbox_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.file_listbox_frame.grid(row=5, column=1, columnspan=3, sticky="nsew", pady=10)

        self.file_listbox = tk.Listbox(self.file_listbox_frame, selectmode=tk.SINGLE, bg="#444444", fg="white", font=("Arial", 12))
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(self.file_listbox_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        ttk.Button(self.main_frame, text="Download Selected", command=self.download_file, style="TButton").grid(row=6, column=1, columnspan=3, pady=5)
        ttk.Button(self.main_frame, text="Delete Selected", command=self.delete_file, style="TButton").grid(row=7, column=1, columnspan=3, pady=5)

        ttk.Button(self.main_frame, text="Logout", command=self.logout, style="TButton").grid(row=8, column=1, columnspan=3, pady=10)

        # Hide main frame initially
        self.main_frame.grid_remove()

        # Configure styles
        self.configure_styles()

    def configure_styles(self):
        # Configure ttk styles for a modern look
        style = ttk.Style(self.root)
        style.theme_use("clam")  # Use the 'clam' theme for a modern look

        # Customize colors and fonts
        style.configure("TFrame", background="#333333")  # Dark gray background
        style.configure("TLabel", background="#333333", foreground="white", font=("Arial", 12))  # White text
        style.configure("TButton", background="#4CAF50", foreground="white", font=("Arial", 12), padding=10)  # Green buttons
        style.map("TButton", background=[("active", "#45a049")])  # Darker green on hover
        style.configure("Accent.TButton", background="#2196F3", foreground="white", font=("Arial", 12, "bold"), padding=10)  # Blue accent buttons
        style.map("Accent.TButton", background=[("active", "#1e88e5")])  # Darker blue on hover

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        session_id, message = self.user_manager.authenticate(username, password)
        if session_id:
            self.current_user = username
            self.login_frame.grid_remove()
            self.main_frame.grid()
            self.update_file_list()
        else:
            messagebox.showerror("Login Failed", message)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        success, message = self.user_manager.register_user(username, password)
        messagebox.showinfo("Registration", message)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filepath)

    def send_file(self):
        recipient = self.recipient_entry.get()
        filepath = self.file_entry.get()
        message = self.message_entry.get()
        success, msg = self.file_manager.share_file(self.current_user, recipient, filepath, message)
        messagebox.showinfo("Send File", msg)
        self.update_file_list()

    def update_file_list(self):
        self.file_listbox.delete(0, tk.END)
        files = self.file_manager.get_shared_files(self.current_user)
        for file_id, metadata in files.items():
            # Include the message in the display
            message = metadata.get("message", "No message")
            self.file_listbox.insert(tk.END, f"{metadata['filename']} (from {metadata['sender']}): {message}")

    def download_file(self):
        selected = self.file_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "No file selected")
            return

        # Get the selected file ID
        file_id = list(self.file_manager.get_shared_files(self.current_user).keys())[selected[0]]

        # Get the logged-in user's password
        password = self.password_entry.get()  # Assuming the password is still in the password entry field

        # Ask the user where to save the file
        output_path = filedialog.asksaveasfilename()

        if output_path:
            # Download the file using the user's password
            success, msg = self.file_manager.download_file(self.current_user, file_id, output_path, password)
            if success:
                messagebox.showinfo("Download", f"File saved to {msg}")
            else:
                messagebox.showerror("Download Failed", msg)

    def delete_file(self):
        selected = self.file_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "No file selected")
            return
        file_id = list(self.file_manager.get_shared_files(self.current_user).keys())[selected[0]]
        success, msg = self.file_manager.delete_shared_file(self.current_user, file_id)
        messagebox.showinfo("Delete File", msg)
        self.update_file_list()

    def logout(self):
        # Clear all input fields and data
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.recipient_entry.delete(0, tk.END)
        self.file_entry.delete(0, tk.END)
        self.message_entry.delete(0, tk.END)
        self.file_listbox.delete(0, tk.END)

        # Reset the current user
        self.current_user = None

        # Switch back to the login frame
        self.main_frame.grid_remove()
        self.login_frame.grid()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileSharingApp(root)
    root.mainloop()