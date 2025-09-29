#!/usr/bin/env python3
"""Interactive starter panel for the encryptor project.

Shortcuts:
  1 - Encrypt
  2 - Decrypt
  9 - Back/Exit (when applicable)

The start panel prints colored output (ANSI escape codes). If your terminal
doesn't support colors the output will still be readable.
"""
import os
import subprocess, platform

def copy_to_clipboard(text: str) -> bool:
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    plat = platform.system()
    try:
        if plat == 'Darwin':
            p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            p.communicate(text.encode('utf-8'))
            return p.returncode == 0
        elif plat == 'Windows':
            p = subprocess.Popen(['clip'], stdin=subprocess.PIPE, shell=True)
            p.communicate(text.encode('utf-8'))
            return p.returncode == 0
        else:
            p = subprocess.Popen(['xclip','-selection','clipboard'], stdin=subprocess.PIPE)
            p.communicate(text.encode('utf-8'))
            if p.returncode == 0:
                return True
            p = subprocess.Popen(['xsel','--clipboard','--input'], stdin=subprocess.PIPE)
            p.communicate(text.encode('utf-8'))
            return p.returncode == 0
    except Exception:
        return False

from pathlib import Path
import json
import sys

from encryptor.core import encrypt_text, decrypt_text, inspect_cipher_meta, DecryptionError

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
FG_CYAN = "\033[36m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_RED = "\033[31m"
FG_MAGENTA = "\033[35m"

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # env overrides
    env_key = os.getenv("MASTER_KEY")
    if env_key is not None:
        cfg["master_key"] = env_key
    env_mk_enabled = os.getenv("MASTER_KEY_ENABLED")
    if env_mk_enabled is not None:
        cfg["master_key_enabled"] = env_mk_enabled.lower() in ("1","true","yes","on")
    return cfg

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def header():
    print(FG_CYAN + BOLD + "=== Modular Python Encryptor (interactive) ===" + RESET)

def main_menu():
    clear()
    header()
    print()
    print(FG_GREEN + "1) Encrypt" + RESET)
    print(FG_YELLOW + "2) Decrypt" + RESET)
    print(FG_MAGENTA + "9) Exit" + RESET)
    print()
    choice = input(FG_CYAN + "Choose an option: " + RESET).strip()
    return choice

def encrypt_flow(cfg):
    clear()
    print(FG_GREEN + BOLD + "-- Encrypt --" + RESET)
    text = input(FG_CYAN + "Enter plaintext to encrypt: " + RESET)
    if text.strip() == "":
        print(FG_RED + "No input provided, returning to menu." + RESET)
        input("Press Enter to continue...")
        return
    try:
        cipher, meta = encrypt_text(text, cfg, return_meta=True)
    except Exception as e:
        print(FG_RED + f"Encryption failed: {e}" + RESET)
        input("Press Enter to continue...")
        return

    # Fancy output
    print()
    print(FG_YELLOW + "[Metadata]" + RESET)
    print(f"Level: {meta['level']} (rounds={meta['rounds']}, salt_length={meta['salt_length']})")
    print(f"Master key used: {FG_GREEN if meta['master_key_used'] else FG_RED}{meta['master_key_used']}{RESET}")
    print(f"Cipher length: {len(cipher)} characters")
    print()
    print(FG_MAGENTA + BOLD + "CIPHER:" + RESET)
    print(cipher)
    print()
    print(FG_CYAN + "(Copy the value above — it is the full encoded cipher string.)" + RESET)
    input("\nPress Enter to return to menu...")

def decrypt_flow(cfg):
    clear()
    print(FG_GREEN + BOLD + "-- Decrypt --" + RESET)
    cipher = input(FG_CYAN + "Enter cipher string to decrypt: " + RESET).strip()
    if cipher == "":
        print(FG_RED + "No cipher provided, returning to menu." + RESET)
        input("Press Enter to continue...")
        return
    # Show meta first
    meta = inspect_cipher_meta(cipher)
    if not meta:
        print(FG_RED + "Input doesn't look like a valid cipher." + RESET)
        input("Press Enter to continue...")
        return
    print()
    print(FG_YELLOW + "[Cipher metadata]" + RESET)
    print(f"Version: {meta.get('v')}")
    print(f"Level: {meta.get('lvl')} (rounds={meta.get('rounds')}, salt_length={meta.get('salt_length')})")
    print(f"Master key required: {FG_GREEN if meta.get('mk') else FG_RED}{meta.get('mk')}{RESET}")
    print()

    # Attempt decryption
    try:
        plaintext = decrypt_text(cipher, cfg)
    except DecryptionError as e:
        print(FG_RED + f"Decryption failed: {e}" + RESET)
        input("Press Enter to continue...")
        return

    print(FG_MAGENTA + BOLD + "PLAINTEXT:" + RESET)
    print(FG_GREEN + plaintext + RESET)
    input("\nPress Enter to return to menu...")

def run():
    cfg = load_config()
    while True:
        choice = main_menu()
        if choice == '1':
            encrypt_flow(cfg)
        elif choice == '2':
            decrypt_flow(cfg)
        elif choice == '9':
            print(FG_CYAN + "Goodbye!" + RESET)
            break
        else:
            print(FG_RED + "Invalid choice, try again." + RESET)
            input("Press Enter to continue...")

if __name__ == '__main__':
    run()
