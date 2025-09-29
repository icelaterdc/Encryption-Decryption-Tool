#!/usr/bin/env python3
"""CLI wrapper for encryption.
Usage: python encryption.py "some text to encrypt"
"""
import argparse
import sys
from pathlib import Path
import json
import os
import subprocess, platform
def copy_to_clipboard(text: str) -> bool:
    """Try to copy `text` to the system clipboard. Returns True on success."""
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
            # try xclip then xsel
            p = subprocess.Popen(['xclip','-selection','clipboard'], stdin=subprocess.PIPE)
            p.communicate(text.encode('utf-8'))
            if p.returncode == 0:
                return True
            p = subprocess.Popen(['xsel','--clipboard','--input'], stdin=subprocess.PIPE)
            p.communicate(text.encode('utf-8'))
            return p.returncode == 0
    except Exception:
        return False

from encryptor.core import encrypt_text

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.json"

def load_config(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def print_encryption_output(cipher: str, meta: dict):
    # Reproduce same output format as start panel (with simple non-colored labels for CLI)
    print(f"Level: {meta['level']} (rounds={meta['rounds']}, salt_length={meta['salt_length']})")
    print(f"Master key used: {meta['master_key_used']}")
    print(f"Cipher length: {len(cipher)} characters")
    print("")
    print("CIPHER:")
    print(cipher)
    print("")
    print("(Copy the value after 'CIPHER:' — it is the full encoded cipher string.)")

def main():
    p = argparse.ArgumentParser(description="Encrypt plaintext into a cipher string.")
    p.add_argument("text", nargs=1, help="Plaintext to encrypt (wrap in quotes)")
    p.add_argument("--config", default=str(DEFAULT_CONFIG), help="Path to config.json")
    args = p.parse_args()

    cfg = load_config(Path(args.config))
    # Allow environment variable to override master_key and master_key_enabled
    env_key = os.getenv("MASTER_KEY")
    if env_key is not None:
        cfg["master_key"] = env_key
    env_mk_enabled = os.getenv("MASTER_KEY_ENABLED")
    if env_mk_enabled is not None:
        cfg["master_key_enabled"] = env_mk_enabled.lower() in ("1","true","yes","on")

    plaintext = args.text[0]

    cipher, meta = encrypt_text(plaintext, cfg, return_meta=True)
    print_encryption_output(cipher, meta)

if __name__ == "__main__":
    main()
