# Modular Python Encryptor/Decryptor Tool

> **This document explains how the encryptor works, how to configure it, and best practices for secure use.**

---

## Table of contents
1. Overview
2. Project structure
3. Features & limitations
4. Configuration (complete schema)
5. How the encryption works (detailed)
6. PBKDF2 (password-based key derivation) explained
7. Master key explained and recommendations
8. CLI & interactive usage (examples)
9. Container format and versioning
10. Troubleshooting & common errors
11. Security best practices
12. Development & contributing
13. License

---

## 1) Overview
This tool provides a reversible encryption scheme intended for educational and small-scale utility purposes. It produces a compact, portable cipher string that contains both metadata and the encrypted payload. 

**Important:** This is *not* a drop-in replacement for well-reviewed, production crypto libraries. For real production systems use vetted libraries such as `libsodium` or `cryptography`.

---

## 2) Project structure
```
modular-python-encryptor/
├── README.md
├── LICENSE
├── .gitignore
├── config.json
├── requirements.txt
├── encrypt.py        # CLI encrypt (short alias)
├── decrypt.py        # CLI decrypt (short alias)
├── start.py          # Interactive terminal panel
├── keys.txt          # (optional) example/generated keys
└── encryptor/
    ├── __init__.py
    ├── core.py      # core algorithm (encrypt/decrypt/inspect)
    └── utils.py     # keystream + permutation helpers
```

---

## 3) Features & limitations
- Modular, easy-to-read Python implementation.
- Configurable **encryption levels** (1/2/3) controlling rounds and per-round salt sizes.
- Two keying modes:
  - **Master key** (static 32-byte secret you provide), or
  - **Password → PBKDF2** (user-friendly passphrase converted to a secure key)
- Interactive terminal UI (`start.py`) with colored output and clipboard copy.

**Limitations / Warnings:**
- This is **custom cryptography** and may have weaknesses. Do not use this where strong security guarantees are required.
- Cipher includes salts and (optionally) PBKDF2 metadata. If `master_key` is used it is not embedded in the cipher.

---

## 4) Configuration (complete schema)
The `config.json` file contains the operational settings. Example (full):

```json
{
  "version": 3,
  "master_key_enabled": true,
  "master_key": "replace-with-your-base64-key-or-empty-if-disabled",
  "password_enabled": false,
  "password": "",
  "pbkdf2_iters": 100000,
  "level": 2,
  "levels": {
    "1": { "rounds": 1, "salt_length": 4 },
    "2": { "rounds": 2, "salt_length": 8 },
    "3": { "rounds": 4, "salt_length": 12 }
  }
}
```

**Field meanings**
- `version` — internal container format version (do not change manually unless migrating).
- `master_key_enabled` (bool) — when `true`, decrypt requires `master_key` unless the cipher embeds PBKDF2 metadata.
- `master_key` (string) — your static key (base64 recommended). Only used when `master_key_enabled` is `true` and `password_enabled` is `false` (by default PBKDF2 takes priority if enabled).
- `password_enabled` (bool) — when `true`, the tool uses PBKDF2 to derive the encryption key from `password`/`PASSWORD` env. During encryption a random PBKDF2 salt is generated and embedded in the cipher.
- `password` (string) — **optional** passphrase. Prefer using environment variable `PASSWORD` for operational security.
- `pbkdf2_iters` (int) — iteration count for PBKDF2. Default `100000`. Larger values increase security but also CPU cost.
- `level` (1/2/3) — default encryption level used unless overridden.
- `levels` — per-level parameters controlling rounds and salt sizes.

**Environment variable overrides**
- `MASTER_KEY` — if set, overrides `config.master_key`
- `PASSWORD` — if set, overrides `config.password`
- `MASTER_KEY_ENABLED` / `PASSWORD_ENABLED` — can override the boolean flags (accepted values: `1,true,yes,on` case-insensitive)

---

## 5) How the encryption works (detailed)
This is a step-by-step description of what `encrypt.py` does internally:

1. **Resolve keying method**
   - If the cipher/operation uses PBKDF2 (i.e. `password_enabled`): derive a 32-byte key using PBKDF2-HMAC-SHA256 with a freshly generated 16-byte salt and `pbkdf2_iters` iterations. Embed that `salt` and `iters` in the cipher so the receiver can derive the same key.
   - Else if `master_key_enabled` is `true`: the provided `master_key` (from config or `MASTER_KEY` env) is used directly as the key material (encoded in UTF-8). *Important:* master key is **not** stored inside the cipher.
   - Else: an empty key (all-zero equivalent) is used — this produces reversible obfuscation but not true keyed secrecy.

2. **Encode plaintext** → get bytes (`utf-8`).

3. **For each round (N = rounds)**:
   - Generate a random per-round `salt` (length per `salt_length` from level settings) and append to `salts` array (this salt is stored in the cipher).
   - Create a deterministic keystream of the plaintext length by hashing `master_key || "||" || salt || "||" || counter` repeatedly with SHA-256 and concatenating digests until enough bytes exist.
   - XOR keystream with the current data bytes.
   - Derive a deterministic permutation seed by hashing `master_key || "::" || salt` (SHA-256) and converting to integer.
   - Produce a permutation of byte indices using Python's `random.Random(seed).shuffle(...)` and apply the permutation to the bytes.

4. **After rounds**: base64-encode the final bytes into `payload` and build the container JSON. Example container keys:
   - `v`: version (e.g. `3`)
   - `lvl`: encryption level (string)
   - `mk`: boolean indicating whether a key was used
   - `pbkdf2`: optional object `{ salt: <hex>, iters: <int> }`
   - `salts`: array of per-round salt hex strings
   - `payload`: base64 string

5. **Serialize container JSON** and then base64 the JSON bytes to produce the final single-line cipher string printed to stdout and copied to the clipboard.

**Decryption** reverses all steps: base64→JSON, read pbkdf2/meta, derive key accordingly, reverse rounds (inverse permutation then XOR), decode UTF-8.

---

## 6) PBKDF2 (password-based key derivation) explained (simple + technical)
**Simple summary:** PBKDF2 transforms a human password into a cryptographically strong key by introducing a random salt and repeating a hash many times.

**Technical details used in this project:**
- PRF: `HMAC-SHA256`
- Salt: 16 bytes (random, stored in container as hex)
- Iterations: configurable via `pbkdf2_iters` (default `100000`)
- Output key length: 32 bytes (256 bits)

**Why salt and iterations matter**
- **Salt** prevents precomputed attacks (rainbow tables) and ensures identical passwords produce different derived keys.
- **Iterations** slow down each guess, making brute-force more expensive for attackers.

**Workflow during encrypt**
- Generate `pbkdf2_salt` (16 bytes). Store in container.
- Derive key = `PBKDF2-HMAC-SHA256(password, pbkdf2_salt, iters, dklen=32)` and use this key as `master_key` for subsequent steps.

**During decrypt**
- Read `pbkdf2` metadata from container, request/obtain password, run PBKDF2 with the stored salt and iters to derive the same key.

---

## 7) Master Key explained and recommendations
- **Format:** The tool accepts `master_key` as a UTF-8 string; we recommend using a base64-encoded 32-byte key (example: `x7O17UAM+Bz2fOogeJgPKRyYHoOdVj1KHLP2sXpGaqY=`).
- **Generation examples**:
  - `openssl rand -base64 32`
  - `python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"`
- **Do not commit** `master_key` to public repositories. Use environment variables or secrets managers (AWS Secrets Manager, Vault, GitHub Secrets) in production.
- **Rotation:** To rotate keys, re-encrypt payloads with the new key. Old ciphers will remain decryptable only with the old key unless re-encrypted.

---

## 8) CLI & interactive usage (examples)
**Encrypt (manual)**
```bash
# Using master_key from env
export MASTER_KEY='x7O17UAM+Bz2fOogeJgPKRyYHoOdVj1KHLP2sXpGaqY='
python encrypt.py "Hello, secret world"
```
**Using password (PBKDF2)**
```bash
export PASSWORD='my passphrase here'
python encrypt.py "Hello with passphrase"
```

**Decrypt (manual)**
```bash
export PASSWORD='my passphrase here'
python decrypt.py "<cipher-string>"
```

**Interactive panel**
```bash
python start.py
# choose 1 = Encrypt, 2 = Decrypt, 9 = Exit
```

**Clipboard behavior**
- The tools attempt to copy results to clipboard automatically using `pyperclip` if available, otherwise platform utilities (`pbcopy`, `clip`, `xclip`, `xsel`) are tried.
- If automatic copy fails, the program prints a helpful message. You can `pip install pyperclip` for a cross-platform python clipboard helper.

**Windows (PowerShell) examples**
```powershell
$env:PASSWORD = 'my passphrase'
python encrypt.py "hi"
```

---

## 9) Container format and versioning
The tool serializes a JSON container and base64-encodes it. A typical container (pretty-printed) looks like:

```json
{
  "v": 3,
  "lvl": "2",
  "mk": true,
  "pbkdf2": { "salt": "a4eb...", "iters": 100000 },
  "salts": ["a1b2c3...", "d4e5f6..."],
  "payload": "<base64-of-encrypted-bytes>"
}
```

- `v` - container format version. If you update the algorithm in the future, increment `v` and handle compatibility in `core.py`.

---

## 10) Troubleshooting & common errors
- **"input is not a valid cipher"** — the string you provided is not a base64-encoded container; make sure you copied the full cipher string.
- **"cipher requires a master_key"** — set `MASTER_KEY` env or `master_key` in config (if cipher was created without PBKDF2).
- **"Password required"** — set `PASSWORD` env or `password` in config if cipher contains `pbkdf2` metadata.
- **Clipboard copy not working** — install `pyperclip` (`pip install pyperclip`) or the platform clipboard helper (`xclip`/`xsel` on Linux, `pbcopy` on macOS).
- **Colored output not showing** — some Windows terminals may not support ANSI colors by default. Use a modern terminal emulator or enable ANSI support.

---

## 11) Security best practices
- **Do not commit secrets** (`master_key`, `password`, `keys.txt`) to version control.
- Prefer environment variables or secret stores for production.
- Use `password_enabled` for human workflows and `master_key_enabled` for automated systems.
- Increase `pbkdf2_iters` for higher security, but balance against CPU constraints.
- For strong confidentiality and authentication in production, prefer an authenticated encryption scheme (e.g. AES-GCM) from a vetted lib.

---

## 12) Development & contributing
- Code is organized under `encryptor/`. Update `core.py` and `utils.py` for algorithm changes.
- Run manual tests: `python encrypt.py "test"` and `python decrypt.py "<cipher>"`.
- Please open an issue or PR with clear reasoning for changes.

---

## 13) License
MIT — see `LICENSE` file.
