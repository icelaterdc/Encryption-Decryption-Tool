"""Core encryption/decryption functions (v3).
Supports optional master_key usage (master_key_enabled flag) and password-based PBKDF2 derivation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import List, Tuple, Optional, Dict

from .utils import derive_keystream, permutation_indices, apply_permutation, invert_permutation

class DecryptionError(Exception):
    pass

def _seed_from(master_key: bytes, salt: bytes) -> int:
    # Convert SHA256(master_key || salt) to an int for seeding random.Random
    h = hashlib.sha256()
    h.update(master_key)
    h.update(b"::")
    h.update(salt)
    return int.from_bytes(h.digest(), "big")

def _derive_key_from_password(password: str, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    if not isinstance(password, (bytes, bytearray)):
        password = password.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=dklen)

def _resolve_master_key_from_config(config: Dict, container_pbkdf2: Optional[Dict] = None) -> Tuple[bytes, Optional[Dict]]:
    """
    Determine the effective master_key bytes based on config and optional container pbkdf2 metadata.
    If config indicates password_enabled or container contains pbkdf2 info, derive key using PBKDF2.

    Returns (master_key_bytes, used_pbkdf2_metadata_or_None)
    """
    # Priority order:
    # 1) If container_pbkdf2 provided (during decrypt), derive using config.password or env PASSWORD
    # 2) Else if config.password_enabled True, derive and produce pbkdf2 metadata for encryption
    # 3) Else if master_key_enabled True, use master_key from config/env
    # 4) Else return empty key (b'')

    # Use env overrides
    import os
    env_password = os.getenv('PASSWORD')
    env_master_key = os.getenv('MASTER_KEY')

    password_enabled = bool(config.get('password_enabled', False))
    master_key_enabled = bool(config.get('master_key_enabled', True))
    pbkdf2_iters = int(config.get('pbkdf2_iters', 100000))

    # If container_pbkdf2 is present, we're decrypting and must use its salt/iters
    if container_pbkdf2 is not None:
        salt = bytes.fromhex(container_pbkdf2.get('salt'))
        iters = int(container_pbkdf2.get('iters', pbkdf2_iters))
        # password source: env PASSWORD overrides config.password
        password = env_password if (env_password is not None) else config.get('password', '')
        if not password:
            raise ValueError('Password required to derive key for this cipher but none provided (set PASSWORD env or config.password)')
        key = _derive_key_from_password(password, salt, iters, dklen=32)
        return key, {'salt': salt.hex(), 'iters': iters}

    # No container metadata: encryption path or decrypt with no pbkdf2
    # If password_enabled in config -> derive and provide metadata
    if password_enabled:
        password = env_password if (env_password is not None) else config.get('password', '')
        if not password:
            raise ValueError('password_enabled is true but no password provided in config or PASSWORD env')
        salt = secrets.token_bytes(16)
        iters = pbkdf2_iters
        key = _derive_key_from_password(password, salt, iters, dklen=32)
        return key, {'salt': salt.hex(), 'iters': iters}

    # Else fallback to master_key if enabled
    if master_key_enabled:
        master_key_raw = env_master_key if (env_master_key is not None) else config.get('master_key', '')
        if not master_key_raw:
            raise ValueError('master_key_enabled is true but no master_key provided in config or MASTER_KEY env')
        return master_key_raw.encode('utf-8'), None

    # No key used
    return b'', None

def encrypt_text(plaintext: str, config: dict, return_meta: bool = False) -> Tuple[str, dict]:
    """
    Encrypt plaintext according to configuration and return a compact cipher string.
    If return_meta is True, also return a metadata dict with level/rounds/salt_length/master_key_used.
    The cipher is: base64( json({v, lvl, mk, pbkdf2: {...}?, salts:[hex...], payload: base64(payload_bytes)}) )
    """
    if not isinstance(plaintext, str):
        raise TypeError('plaintext must be a str')

    level = config.get('level', 2)
    level_key = str(level)
    levels = config.get('levels', {})
    if level_key not in levels:
        raise ValueError(f"Unknown level '{level}' in config")

    rounds = int(levels[level_key]['rounds'])
    salt_length = int(levels[level_key]['salt_length'])

    # Resolve master key: may derive from password (and produce pbkdf2 metadata)
    master_key, pbkdf2_meta = _resolve_master_key_from_config(config, container_pbkdf2=None)

    data = plaintext.encode('utf-8')
    salts: List[bytes] = []

    # Perform N rounds of (XOR keystream -> permutation)
    for _ in range(rounds):
        salt = secrets.token_bytes(salt_length)
        salts.append(salt)

        # XOR with keystream (master_key may be empty if disabled)
        ks = derive_keystream(master_key, salt, len(data))
        data = bytes([b ^ k for b, k in zip(data, ks)])

        # deterministic permutation using seed derived from master_key + salt
        seed = _seed_from(master_key, salt)
        indices = permutation_indices(len(data), seed)
        data = apply_permutation(data, indices)

    # Final payload encoding
    payload_b64 = base64.b64encode(data).decode('ascii')
    salts_hex = [s.hex() for s in salts]

    container = {
        'v': 3,
        'lvl': level_key,
        'mk': True if (master_key and len(master_key) > 0) else False,
        'salts': salts_hex,
        'payload': payload_b64,
    }

    if pbkdf2_meta is not None:
        container['pbkdf2'] = {'salt': pbkdf2_meta['salt'], 'iters': int(pbkdf2_meta['iters'])}

    json_bytes = json.dumps(container, separators=(',', ':')).encode('utf-8')
    final = base64.b64encode(json_bytes).decode('ascii')

    meta = {
        'level': int(level_key),
        'rounds': rounds,
        'salt_length': salt_length,
        'master_key_used': bool(container['mk']),
        'salts_count': len(salts_hex),
    }

    if return_meta:
        return final, meta
    return final

def decrypt_text(cipher: str, config: dict) -> str:
    """
    Decrypt the cipher string created by `encrypt_text` and return plaintext.
    Raises DecryptionError on failure.
    """
    if not isinstance(cipher, str):
        raise TypeError('cipher must be a str')

    # Load container
    try:
        json_bytes = base64.b64decode(cipher.encode('ascii'))
        container = json.loads(json_bytes)
    except Exception as e:
        raise DecryptionError('input is not a valid cipher (base64/json decode failed)') from e

    if container.get('v') not in (2,3):
        raise DecryptionError('unsupported cipher version')

    # Extract pbkdf2 metadata if present
    pbkdf2_meta = container.get('pbkdf2')

    # Resolve master key: when pbkdf2_meta present, pass it to resolver to derive using provided salt/iters
    try:
        master_key, _used_meta = _resolve_master_key_from_config(config, container_pbkdf2=pbkdf2_meta) if pbkdf2_meta else _resolve_master_key_from_config(config, container_pbkdf2=None)
    except Exception as e:
        raise DecryptionError(str(e)) from e

    salts_hex = container.get('salts')
    payload_b64 = container.get('payload')
    if not isinstance(salts_hex, list) or not isinstance(payload_b64, str):
        raise DecryptionError('cipher missing required fields')

    try:
        data = base64.b64decode(payload_b64.encode('ascii'))
    except Exception as e:
        raise DecryptionError('payload is not valid base64') from e

    # Reverse rounds in reverse order
    for salt_hex in reversed(salts_hex):
        salt = bytes.fromhex(salt_hex)
        seed = _seed_from(master_key, salt)
        indices = permutation_indices(len(data), seed)

        # invert permutation
        data = invert_permutation(data, indices)

        # XOR with keystream
        ks = derive_keystream(master_key, salt, len(data))
        data = bytes([b ^ k for b, k in zip(data, ks)])

    try:
        return data.decode('utf-8')
    except Exception as e:
        raise DecryptionError('decrypted bytes could not be decoded as UTF-8') from e

def inspect_cipher_meta(cipher: str) -> dict:
    """Return basic metadata from the cipher without requiring config or master key.
    Parses the top-level container to get version, level and mk flag. Also returns rounds/salt_length if level found in global default mapping.
    """
    try:
        json_bytes = base64.b64decode(cipher.encode('ascii'))
        container = json.loads(json_bytes)
    except Exception:
        return {}

    meta = {
        'v': container.get('v'),
        'lvl': container.get('lvl'),
        'mk': container.get('mk', False),
        'salts_count': len(container.get('salts', [])),
    }
    # Try to map level to rounds/salt_length from a small built-in mapping
    level = container.get('lvl')
    mapping = {'1': {'rounds':1, 'salt_length':4}, '2': {'rounds':2, 'salt_length':8}, '3': {'rounds':4, 'salt_length':12}}
    if level in mapping:
        meta.update(mapping[level])
    # PBKDF2 info
    if 'pbkdf2' in container:
        meta['pbkdf2'] = {'salt': container['pbkdf2'].get('salt'), 'iters': int(container['pbkdf2'].get('iters', 0))}
    return meta
