#!/usr/bin/env python3
"""File Integrity & Digital Signature CLI Tool.

Lets a Sender sign files and a Receiver verify their integrity and origin
using SHA-256 hashing and RSA digital signatures.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


CHUNK_SIZE = 65536
EXCLUDED_EXTENSIONS = {".pem", ".sig"}
EXCLUDED_NAMES = {"metadata.json"}


def hash_file(filepath):
    """Compute the SHA-256 hex digest of a file, reading in chunks."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def collect_files(directory):
    """Recursively collect all non-hidden, non-excluded files in a directory."""
    files = []
    for root, dirs, filenames in os.walk(directory):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in filenames:
            if name.startswith("."):
                continue
            if name in EXCLUDED_NAMES:
                continue
            if os.path.splitext(name)[1] in EXCLUDED_EXTENSIONS:
                continue
            files.append(os.path.join(root, name))
    return files


def cmd_hash(args):
    """Hash a single file and print its SHA-256 digest."""
    try:
        digest = hash_file(args.filepath)
    except FileNotFoundError:
        print(f"Error: File not found: {args.filepath}", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: Path is a directory: {args.filepath}", file=sys.stderr)
        sys.exit(1)
    print(f"SHA-256: {digest}")


def cmd_manifest(args):
    """Generate a metadata manifest (metadata.json) for a directory."""
    directory = args.directory
    if not os.path.isdir(directory):
        print(f"Error: Not a directory: {directory}", file=sys.stderr)
        sys.exit(1)

    file_paths = collect_files(directory)
    files_dict = {}
    for fp in sorted(file_paths):
        rel = os.path.relpath(fp, directory)
        files_dict[rel] = hash_file(fp)

    manifest = {
        "files": files_dict,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    output = args.o if args.o else os.path.join(directory, "metadata.json")
    with open(output, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Hashed {len(files_dict)} file(s).")
    print(f"Manifest written to: {output}")


def cmd_check(args):
    """Verify files against a manifest and report discrepancies."""
    directory = args.directory
    manifest_path = args.m if args.m else os.path.join(directory, "metadata.json")

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except FileNotFoundError:
        print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in manifest: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    return run_check(directory, manifest)


def run_check(directory, manifest):
    """Run integrity check logic. Returns True if all OK, False otherwise."""
    files_map = manifest.get("files", {})
    ok, modified, missing = [], [], []

    for rel_path, expected_hash in sorted(files_map.items()):
        full_path = os.path.join(directory, rel_path)
        if not os.path.exists(full_path):
            missing.append(rel_path)
        else:
            actual_hash = hash_file(full_path)
            if actual_hash == expected_hash:
                ok.append(rel_path)
            else:
                modified.append(rel_path)

    # Detect new files
    current_files = collect_files(directory)
    current_rels = {os.path.relpath(fp, directory) for fp in current_files}
    manifest_rels = set(files_map.keys())
    new_files = sorted(current_rels - manifest_rels)

    # Report
    for f in ok:
        print(f"  [OK]       {f}")
    for f in modified:
        print(f"  [MODIFIED] {f}")
    for f in missing:
        print(f"  [MISSING]  {f}")
    for f in new_files:
        print(f"  [NEW]      {f}")

    print()
    print(f"OK: {len(ok)}  MODIFIED: {len(modified)}  MISSING: {len(missing)}  NEW: {len(new_files)}")

    all_good = not modified and not missing and not new_files
    if all_good:
        print("All files intact.")
    else:
        print("Integrity issues detected.")
    return all_good


def cmd_keygen(args):
    """Generate a 2048-bit RSA key pair."""
    keyname = args.o if args.o else "sender"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_path = f"{keyname}_private.pem"
    public_path = f"{keyname}_public.pem"

    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")


def cmd_sign(args):
    """Sign a metadata manifest with a private key."""
    try:
        with open(args.private_key, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"Error: Private key not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid private key: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.metadata, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Metadata file not found: {args.metadata}", file=sys.stderr)
        sys.exit(1)

    digest = hashlib.sha256(data).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    output = args.o if args.o else args.metadata.replace(".json", ".sig")
    with open(output, "wb") as f:
        f.write(signature)

    print(f"Signature written to: {output}")


def cmd_verify(args):
    """Verify signature on a manifest then check file integrity."""
    # Load public key
    try:
        with open(args.public_key, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print(f"Error: Public key not found: {args.public_key}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid public key: {e}", file=sys.stderr)
        sys.exit(1)

    # Load signature
    try:
        with open(args.signature, "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        print(f"Error: Signature file not found: {args.signature}", file=sys.stderr)
        sys.exit(1)

    # Load metadata
    try:
        with open(args.metadata, "rb") as f:
            metadata_bytes = f.read()
    except FileNotFoundError:
        print(f"Error: Metadata file not found: {args.metadata}", file=sys.stderr)
        sys.exit(1)

    # Step 1: Verify signature
    digest = hashlib.sha256(metadata_bytes).digest()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("SIGNATURE: INVALID")
        print("The metadata file signature does not match. It may have been tampered with.")
        sys.exit(1)

    print("SIGNATURE: VALID")
    print()

    # Step 2: Integrity check
    manifest = json.loads(metadata_bytes)
    all_good = run_check(args.directory, manifest)

    if not all_good:
        sys.exit(1)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="File Integrity & Digital Signature Tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # hash
    p_hash = subparsers.add_parser("hash", help="Compute SHA-256 hash of a file")
    p_hash.add_argument("filepath", help="Path to the file to hash")

    # manifest
    p_manifest = subparsers.add_parser("manifest", help="Generate metadata manifest for a directory")
    p_manifest.add_argument("directory", help="Directory to scan")
    p_manifest.add_argument("-o", help="Output path for metadata.json")

    # check
    p_check = subparsers.add_parser("check", help="Verify files against a manifest")
    p_check.add_argument("directory", help="Directory to check")
    p_check.add_argument("-m", help="Path to metadata.json")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate RSA key pair")
    p_keygen.add_argument("-o", help="Key name prefix (default: sender)")

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a metadata manifest")
    p_sign.add_argument("metadata", help="Path to metadata.json")
    p_sign.add_argument("-k", dest="private_key", required=True, help="Path to private key PEM")
    p_sign.add_argument("-o", help="Output path for signature file")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify signature and file integrity")
    p_verify.add_argument("directory", help="Directory to verify")
    p_verify.add_argument("-m", dest="metadata", required=True, help="Path to metadata.json")
    p_verify.add_argument("-s", dest="signature", required=True, help="Path to signature file")
    p_verify.add_argument("-k", dest="public_key", required=True, help="Path to public key PEM")

    args = parser.parse_args()

    commands = {
        "hash": cmd_hash,
        "manifest": cmd_manifest,
        "check": cmd_check,
        "keygen": cmd_keygen,
        "sign": cmd_sign,
        "verify": cmd_verify,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
