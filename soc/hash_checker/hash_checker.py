"""Hash checker and malware IOC matcher for SentinelPulse SOC Analytics.

Identifies the algorithm behind a hash string by length, computes file
hashes on demand, and matches results against a small built-in set of
known indicators. A quick triage tool for "is this file/hash known bad?"
questions during incident response.

Usage:
    python soc/hash_checker/hash_checker.py --hash <sha256>
    python soc/hash_checker/hash_checker.py --file suspicious.bin

Author: Mohamed Taher
GitHub: https://github.com/MohamedxTaher
LinkedIn: https://www.linkedin.com/in/mohamed-taherx/
"""

import argparse
import hashlib
import os
import sys

KNOWN_MALWARE = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file — often used in testing",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file",
    "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Known malware sample",
}

HASH_PATTERNS = {
    32: "MD5",
    40: "SHA-1",
    56: "SHA-224",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}


def identify_hash(hash_string):
    """Best-effort algorithm identification based on hash length."""
    return HASH_PATTERNS.get(len(hash_string.strip()), "Unknown")


def check_hash(hash_string):
    """Return the IOC description if the hash is a known indicator."""
    return KNOWN_MALWARE.get(hash_string.lower().strip())


def hash_file(filepath):
    """Compute MD5, SHA-1 and SHA-256 digests for a file."""
    try:
        with open(filepath, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(f"error: cannot read {filepath}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main():
    """CLI entry point for the hash checker."""
    cli = argparse.ArgumentParser(
        prog="sentinelpulse-hashcheck",
        description="Identify hash type and check against known malware",
    )
    cli.add_argument("--hash", help="Hash string to check")
    cli.add_argument("--file", help="File to hash and check")
    args = cli.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            raise SystemExit(1)

        hashes = hash_file(args.file)
        print(f"\nFile     : {args.file}")
        for algo, digest in hashes.items():
            match = check_hash(digest)
            status = f"MALWARE DETECTED — {match}" if match else "Clean"
            print(f"{algo.upper():<8} : {digest}  [{status}]")

    elif args.hash:
        digest = args.hash.strip()
        algo = identify_hash(digest)
        match = check_hash(digest)
        print(f"\nHash     : {digest}")
        print(f"Type     : {algo}")
        if match:
            print(f"Status   : MALWARE DETECTED — {match}")
        else:
            print("Status   : Clean — not found in IOC database")

    else:
        cli.print_help()
        print("\nProvide --hash or --file.")


if __name__ == "__main__":
    main()
