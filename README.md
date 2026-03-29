# File Integrity & Digital Signature CLI Tool

A command-line tool that lets a **Sender** sign files and a **Receiver** verify their integrity and origin using **SHA-256 hashing** and **RSA digital signatures**.

## Demo

[![Watch the demo on YouTube](https://img.youtube.com/vi/NNgYIUrmYuU/maxresdefault.jpg)](https://youtu.be/NNgYIUrmYuU)

## Requirements

- Python 3.8+
- `cryptography` library

```bash
pip install cryptography
```

## Usage

### Hash a File

Compute the SHA-256 digest of any file.

```bash
python integrity.py hash <filepath>
```

**Example:**

```bash
python integrity.py hash report.pdf
# SHA-256: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
```

### Generate a Manifest

Recursively scan a directory and produce a `metadata.json` containing the SHA-256 hash of every file.

```bash
python integrity.py manifest <directory> [-o output_path]
```

- Hidden files/folders (starting with `.`) are skipped.
- `.pem`, `.sig`, and `metadata.json` files are excluded automatically.
- Defaults to writing `metadata.json` inside the scanned directory.

**Example:**

```bash
python integrity.py manifest ./project_files
# Hashed 12 file(s).
# Manifest written to: ./project_files/metadata.json
```

### Check Integrity

Compare files in a directory against a previously generated manifest.

```bash
python integrity.py check <directory> [-m metadata.json]
```

Reports each file as one of:

| Status       | Meaning                                      |
|--------------|----------------------------------------------|
| **OK**       | Hash matches the manifest                    |
| **MODIFIED** | File exists but hash differs (tampered)      |
| **MISSING**  | Listed in manifest but not found on disk     |
| **NEW**      | Found on disk but not listed in the manifest |

Exits with code `0` if everything is OK, `1` if any issues are found.

**Example:**

```bash
python integrity.py check ./project_files
#   [OK]       src/main.py
#   [MODIFIED] config.yaml
#   [MISSING]  old_script.sh
#
# OK: 1  MODIFIED: 1  MISSING: 1  NEW: 0
# Integrity issues detected.
```

### Generate RSA Key Pair

Generate a 2048-bit RSA key pair for signing and verification.

```bash
python integrity.py keygen [-o keyname]
```

- Default key name prefix is `sender`.
- Produces `<keyname>_private.pem` and `<keyname>_public.pem`.

**Example:**

```bash
python integrity.py keygen -o sender
# Private key: sender_private.pem
# Public key:  sender_public.pem
```

### Sign a Manifest

Sign a `metadata.json` file using a private key (RSA-PSS with SHA-256).

```bash
python integrity.py sign <metadata.json> -k <private_key.pem> [-o output.sig]
```

**Example:**

```bash
python integrity.py sign ./project_files/metadata.json -k sender_private.pem
# Signature written to: ./project_files/metadata.sig
```

### Verify Signature and Integrity

Verify the digital signature on a manifest, then check all file hashes.

```bash
python integrity.py verify <directory> -m <metadata.json> -s <signature.sig> -k <public_key.pem>
```

- **Step 1:** Validates the RSA signature on the manifest.
- **Step 2:** If the signature is valid, checks every file hash against the manifest.
- Exits `0` only if both the signature and all file hashes pass.

**Example:**

```bash
python integrity.py verify ./project_files \
  -m ./project_files/metadata.json \
  -s metadata.sig \
  -k sender_public.pem
# SIGNATURE: VALID
#
#   [OK]       src/main.py
#   [OK]       config.yaml
#
# OK: 2  MODIFIED: 0  MISSING: 0  NEW: 0
# All files intact.
```

## Full Workflow

```bash
# --- Sender side ---
python integrity.py keygen -o sender
python integrity.py manifest ./project_files
python integrity.py sign ./project_files/metadata.json -k sender_private.pem

# Transfer: project_files/, metadata.sig, and sender_public.pem to the receiver

# --- Receiver side ---
python integrity.py verify ./project_files \
  -m ./project_files/metadata.json \
  -s metadata.sig \
  -k sender_public.pem
```

## How It Works

1. **Hashing** — Each file is read in 64 KB chunks and hashed with SHA-256, making it memory-efficient for large files.
2. **Manifest** — A JSON file maps every relative file path to its SHA-256 digest, along with a creation timestamp.
3. **Signing** — The manifest's SHA-256 digest is signed with the sender's RSA private key using PSS padding (MGF1/SHA-256, max salt length).
4. **Verification** — The receiver uses the sender's public key to verify the signature, confirming the manifest hasn't been altered. Then each file hash is re-checked against the manifest to detect tampering, deletions, or additions.

## License

MIT
