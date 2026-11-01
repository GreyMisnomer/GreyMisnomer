# GreyMisnomer Sovereign Instance Starter Kit

> **"The protocol doesn't compete with governments — it serves them."**  
> — [07_VISION.md](file:///Users/pritvi/Desktop/projects/GreyMisnomer_r1/07_VISION.md)

This directory provides the complete turnkey deployment template for sovereign statutory bodies (such as India's **Bureau of Energy Efficiency (BEE)** or **Grid Controller of India** for the Carbon Credit Trading Scheme - CCTS), regional authorities, or private environmental asset registries.

---

## 🏛 What is a Sovereign Instance?

A Sovereign Instance runs the **exact same deterministic mathematical rules** as the GreyMisnomer protocol, but with:
1. **Its Own Chain ID:** Absolute cryptographic domain separation (events from one registry cannot be replayed or cross-minted on another).
2. **Its Own Root Authority Key:** The statutory body controls accreditation and revocation of Verification & Validation Bodies (VVBs).
3. **Its Own Sequencer Key:** The statutory operator signs checkpoints and commits blocks to the ledger.
4. **Zero Vendor Lock-in & Zero Licensing Fees:** 100% open-source under the MIT license with $0 ongoing infrastructure costs.

---

## 🚀 Quick Setup (3 Steps)

### Step 1: Run the Bootstrap Script
```bash
chmod +x setup.sh
./setup.sh --chain-name "CCTS-India-Alpha"
```

The script will:
- Generate your Root Authority Ed25519 identity key.
- Generate your Sequencer Ed25519 identity key.
- Encrypt both keys into password-protected `.gmkey` keystores (PBKDF2 + AES-256-GCM).
- Create a canonical Genesis event establishing your sovereign `chain_id`.
- Generate `events.jsonl` and initial `manifest.json`.

### Step 2: Configure Sequencer GitHub Actions
1. Fork or push your sovereign repository to GitHub.
2. In your repo: **Settings → Secrets and variables → Actions → New repository secret**.
3. Add `SEQUENCER_KEY` (paste the encrypted `.gmkey` or raw hex seed).
4. Add `GM_PASSPHRASE` (the passphrase used to unlock the sequencer keystore).

### Step 3: Enable Free Static Verification Portal
1. In your repo: **Settings → Pages**.
2. Set Source to **GitHub Actions** (or Deploy from branch `main` folder `/docs`).
3. Your sovereign verification portal is immediately live at:
   `https://<your-org>.github.io/<your-repo>/`

---

## 📊 What You Get Out-of-the-Box ($0 Cost)

| Capability | Provided By Protocol |
|---|---|
| **Deterministic State Machine** | Pure `apply(state, event)` state transitions in Rust & WASM |
| **Tamper-Evident Ledger** | BLAKE3 hash-chained append-only `events.jsonl` |
| **Supply Conservation** | Mathematical Invariants 1–7 preventing double-counting and inflation |
| **Cryptographic Authorization** | Invariants A1–A3 enforcing detached Ed25519 digital signatures |
| **In-Browser Full Node** | Regulators and citizens audit the chain locally via WebAssembly |
| **Zero-Gas Mempool** | Transparent transaction ingestion via GitHub Issues |
| **Bitcoin Time-Stamping** | Cryptographic anchoring via OpenTimestamps (`events.jsonl.ots`) |
| **Multi-Mirror Redundancy** | Automatic distribution to IPFS and Internet Archive Wayback Machine |
