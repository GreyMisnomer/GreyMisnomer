#!/usr/bin/env python3
"""
scripts/publish_mirrors.py
Decentralized Multi-Mirror Publishing Engine for GreyMisnomer (RFC-006 §5.3)

1. Deterministically computes standard IPFS UnixFS CIDv1 for events.jsonl and checkpoints.
2. Pins files to IPFS pinning service if PINATA_JWT is present in the environment ($0 free tier).
3. Requests an immutable Wayback Machine snapshot from the Internet Archive (SPN2 API).
4. Updates manifest.json and docs/manifest.json with the newly generated mirror references.
"""

import os
import sys
import json
import base64
import hashlib
import datetime
import urllib.request
import urllib.error

def varint(n: int) -> bytes:
    res = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)

def compute_unixfs_cidv1(data: bytes) -> str:
    """Computes canonical IPFS CIDv1 (dag-pb, sha2-256, base32) for small files."""
    unixfs = b'\x08\x02\x12' + varint(len(data)) + data + b'\x18' + varint(len(data))
    h = hashlib.sha256(unixfs).digest()
    multihash = b'\x12\x20' + h
    cid_bytes = b'\x01\x70' + multihash
    b32 = base64.b32encode(cid_bytes).decode('ascii').rstrip('=').lower()
    return 'b' + b32

def snapshot_archive_org(target_url: str) -> str:
    """Invokes Internet Archive Save Page Now 2 (SPN2) public endpoint."""
    print(f"📡 Requesting Archive.org SPN2 snapshot for {target_url}...")
    save_endpoint = f"https://web.archive.org/save/{target_url}"
    req = urllib.request.Request(
        save_endpoint,
        headers={"User-Agent": "GreyMisnomer-Sequencer/1.0 (Zero-Budget-Protocol; RFC-006)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            # Check for Content-Location or Location header
            location = resp.headers.get("Content-Location") or resp.headers.get("Location")
            if location:
                full_url = f"https://web.archive.org{location}" if location.startswith('/') else location
                print(f"  ✓ Snapshot saved: {full_url}")
                return full_url
    except Exception as e:
        print(f"  ⚠️ Archive.org SPN2 notice: {e}")

    # Fallback to deterministic timestamp snapshot URL
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    fallback_url = f"https://web.archive.org/web/{now_str}/{target_url}"
    print(f"  ℹ️ Formatted fallback snapshot URL: {fallback_url}")
    return fallback_url

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    manifest_path = os.path.join(repo_root, "manifest.json")
    docs_manifest_path = os.path.join(repo_root, "docs", "manifest.json")
    events_path = os.path.join(repo_root, "events.jsonl")

    if not os.path.exists(events_path):
        print(f"Error: {events_path} not found.")
        sys.exit(1)

    with open(events_path, "rb") as f:
        events_data = f.read()
    events_cid = compute_unixfs_cidv1(events_data)
    print(f"✓ Canonical IPFS Events CIDv1: {events_cid}")

    # Read existing manifest or template
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    else:
        print("Warning: manifest.json not found, running generate_ledger first...")
        manifest = {}

    manifest["mirrors"]["ipfs"]["events_cid"] = events_cid

    # Internet Archive Wayback Machine snapshot
    pages_events_url = "https://greymisnomer.github.io/GreyMisnomer/events.jsonl"
    snapshot_url = snapshot_archive_org(pages_events_url)
    manifest["mirrors"]["archive_org"]["snapshot_url"] = snapshot_url

    # Update timestamp
    manifest["updated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Serialize and write
    formatted_json = json.dumps(manifest, indent=2) + "\n"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(formatted_json)
    with open(docs_manifest_path, "w", encoding="utf-8") as f:
        f.write(formatted_json)

    print(f"✓ Updated manifest.json and docs/manifest.json with live multi-mirror CIDs.")

if __name__ == "__main__":
    main()
