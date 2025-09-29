"""Utility helpers: keystream derivation, deterministic permutation helpers."""
from __future__ import annotations

import hashlib
import random
from typing import List

def derive_keystream(master_key: bytes, salt: bytes, length: int) -> bytes:
    """
    Deterministic keystream derived from master_key + salt using repeated SHA256.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        hasher = hashlib.sha256()
        hasher.update(master_key)
        hasher.update(b"||")
        hasher.update(salt)
        hasher.update(b"||")
        hasher.update(counter.to_bytes(4, "big"))
        out.extend(hasher.digest())
        counter += 1
    return bytes(out[:length])

def permutation_indices(length: int, seed_int: int) -> List[int]:
    """
    Generate a deterministic permutation of indices [0..length-1] using Python's random.Random with a derived integer seed.
    """
    if length <= 1:
        return list(range(length))
    rnd = random.Random(seed_int)
    indices = list(range(length))
    rnd.shuffle(indices)
    return indices

def apply_permutation(data: bytes, indices: List[int]) -> bytes:
    """
    Apply permutation to `data` where the `i`-th byte moves to position `indices[i]`.
    That is: result[ indices[i] ] = data[i]
    """
    if len(data) == 0:
        return data
    out = bytearray(len(data))
    for i, newpos in enumerate(indices):
        out[newpos] = data[i]
    return bytes(out)

def invert_permutation(data: bytes, indices: List[int]) -> bytes:
    """
    Inverse of apply_permutation: restores original order.
    If apply_permutation produced result where result[indices[i]] = original[i],
    then invert_permutation returns original.
    """
    if len(data) == 0:
        return data
    out = bytearray(len(data))
    for i, newpos in enumerate(indices):
        out[i] = data[newpos]
    return bytes(out)
