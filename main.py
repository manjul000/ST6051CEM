#!/usr/bin/env python3

"""
Main entry point for the secure file sharing application.
"""

import sys

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "gui":
        from gui_interface import SecureFileSharingApp
        import tkinter as tk
        root = tk.Tk()
        app = SecureFileSharingApp(root)
        root.mainloop()
    else:
        from cli_interface import cli_main
        cli_main()

if __name__ == "__main__":
    main()