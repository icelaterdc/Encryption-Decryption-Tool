#!/usr/bin/env python3
"""CLI wrapper for decryption.
Usage: python decryption.py "<cipher-string>"
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

from encryptor.core import decrypt_text, DecryptionError, inspect_cipher_meta

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.json"

def load_config(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def print_decryption_output(plaintext: str, meta: dict):
    print(f"Cipher version: {meta.get('v')}")
    print(f"Level stored in cipher: {meta.get('lvl')} (rounds={meta.get('rounds')}, salt_length={meta.get('salt_length')})")
    print(f"Master key used in cipher: {meta.get('mk')}")
    print("")
    print("PLAINTEXT:")
    print(plaintext)

def main():
    p = argparse.ArgumentParser(description="Decrypt a cipher string produced by this tool.")
    p.add_argument("cipher", nargs=1, help="Cipher string to decrypt (wrap in quotes)")
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

    cipher = args.cipher[0]

    try:
        meta = inspect_cipher_meta(cipher)
        plaintext = decrypt_text(cipher, cfg)
    except DecryptionError as e:
        print(f"Decryption failed: {e}")
        sys.exit(2)

    print_decryption_output(plaintext, meta)

if __name__ == "__main__":
    main()
