# Cryptographic Verification Guide

> **"Verify, don't trust."** — GreyMisnomer Security Standard

Every official release of `grey-misnomer-cli` is published with cryptographic checksums (`SHA256SUMS.txt`) and signed with the project release GPG key, adhering to the security distribution model established by Bitcoin Core.

---

## 1. Verify Release Checksum (SHA-256)

After downloading the release archive for your platform from [GitHub Releases](https://github.com/GreyMisnomer/GreyMisnomer/releases):

### Linux
```bash
# Compute archive SHA-256
sha256sum grey-misnomer-cli-x86_64-unknown-linux-gnu.tar.gz

# Or verify against SHA256SUMS.txt
sha256sum --ignore-missing -c SHA256SUMS.txt
```

### macOS
```bash
# Compute archive SHA-256
shasum -a 256 grey-misnomer-cli-aarch64-apple-darwin.tar.gz

# Or verify against SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt
```

### Windows (PowerShell)
```powershell
Get-FileHash grey-misnomer-cli-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

---

## 2. Verify GPG Release Signature

Download `SHA256SUMS.txt` and `SHA256SUMS.txt.asc` from the release assets:

### Step 1: Import Project GPG Public Key
```bash
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "4A8B9C1E2F3D4E5F"
# Or import from local repository:
# gpg --import keys/release-signing-key.pub
```

### Step 2: Verify the Signature
```bash
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
```

A valid signature confirms:
1. The checksums were published directly by the authorized release maintainer.
2. The release archive has not been modified or tampered with in transit.

---

## 3. Verify the Ledger State & Bitcoin Anchors

Once you have extracted `./grey-misnomer-cli`, verify the canonical ledger:

```bash
# 1. Full deterministic replay of all events & invariant checks
./grey-misnomer-cli replay events.jsonl

# 2. Replay with signed checkpoint audit
./grey-misnomer-cli replay events.jsonl --checkpoints checkpoints

# 3. Verify Bitcoin Proof via OpenTimestamps (independent calendar verification)
ots verify events.jsonl.ots
```
