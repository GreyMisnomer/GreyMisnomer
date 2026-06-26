# GreyMisnomer

> **A zero-trust, immutably-auditable carbon credit registry that runs entirely in the browser.**

Like Bitcoin Core, but for carbon credits. GreyMisnomer solves the opacity and double-counting issues in voluntary carbon markets by moving the core registry logic—including Merkle proofs, invariants, and credit batching—into a cryptographically verifiable WebAssembly module.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-orange)]()

---

## ⚡ Try it Live
**[Open the Interactive Simulator](https://greymisnomer.github.io/GreyMisnomer/)**

The entire 7-step protocol (MRV data upload → Merkle Commitment → Minting → Transfer → Partial Retirement → Audit Export) is available to test directly in your browser. **No backend or database is required.**

---

## 🎯 Vision

Build **registry-first infrastructure** for carbon markets where:
- **Registry > Market**: Separation of credit legitimacy from price discovery
- **Proof-of-Integrity (PoI)**: Cryptographic proof before minting
- **Proof-of-Offset (PoO)**: Irreversible consumption receipt
- **Serialization**: Every credit uniquely tracked

**Not a marketplace. A settlement layer.**

---

## 🏗 Architecture

GreyMisnomer moves the state machine out of a trusted backend and into the client browser:

```mermaid
graph LR
    A[Rust Protocol Core] -->|wasm-pack| B(WebAssembly Module)
    B -->|Loaded by| C[app.html Simulator]
    C -->|Generates| D[ZIP Audit Artifacts]
    C -->|Verifies| E[Merkle Proofs]
```

1. **Rust Library (`grey-misnomer-core`)**: Implements the strict RFC invariants, BLAKE3 hashing, and supply arithmetic.
2. **WASM Bindings (`grey-misnomer-wasm`)**: Exposes the Rust state machine to JavaScript.
3. **Web Interface (`docs/app.html`)**: A 100% client-side simulator where project developers can walk through the lifecycle of a carbon credit and export their cryptographic proofs as JSON/PDF artifacts.

---

## 📜 Invariants Enforced
The WASM core mathematically prevents:
- **Replay attacks**: A Proof-of-Integrity (PoI) can only be minted into credits exactly once.
- **Supply inflation**: Minted amounts must exactly match the length of the serial number range.
- **Double spending**: Credit transfers and retirements track precise serial slices; you cannot transfer overlapping ranges.
- **Tampering**: All MRV (Measurement, Reporting, and Verification) sensor data is committed to a BLAKE3 Merkle tree before minting.

---

## 📂 Project Structure
- [`src/`](./src/) — Rust protocol core (`grey-misnomer-core`) and WASM bindings (`grey-misnomer-wasm`).
- [`docs/`](./docs/) — The static WebAssembly front-end and interactive simulator.
- [`architecture/`](./architecture/) — Architectural documents and system diagrams.
- [`research/`](./research/) — Papers, references, standards, and specifications.
- [`governance/`](./governance/) — Voluntary market rules, standards, policy definitions & compliance docs.
- [`deployments/`](./deployments/) — Docker, IaC, K8s, and Terraform scripts (infrastructure).
- [`poc/`](./poc/) — Experimental proof-of-concept implementations.
- [`tests/`](./tests/) — Integration and unit tests for the core registry logic.
- [`roadmap/`](./roadmap/) — Future project milestones and features.

---

## 🚀 Quick Start (Local Development)

If you want to run the simulator locally and compile the Rust protocol yourself:

**Prerequisites:**
- Rust (`rustup default stable`)
- `wasm32-unknown-unknown` target
- `wasm-pack`
- Node.js (for `http-server`)

**1. Clone the repository**
```bash
git clone https://github.com/PrabhatKarlekar/GreyMisnomer.git
cd GreyMisnomer
```

**2. Build the WASM module**
```bash
cd src/wasm
wasm-pack build --target web --out-dir ../../docs/pkg --out-name grey_misnomer_wasm
```

**3. Serve the web app**
```bash
cd ../../docs
npx http-server -p 8080 --cors -c-1
```
Open `http://localhost:8080` in your browser.

---

## 🔗 Links & Documentation

- **Website/Simulator**: https://greymisnomer.github.io/GreyMisnomer/
- **Discord**: https://discord.gg/CZXXPJUNM
- **Reddit**: https://reddit.com/r/GreyMisnomer
- **Whitepaper**: [Design Document](architecture/desgin_document_v2.pdf)
- **Q&A**: [Questions & Answers](architecture/qna_document_v1.pdf)
- **Diagrams**: [System Architecture](architecture/diagrams/)

---

## 🏗️ Current Phase: Foundation (Year 0-1)

**Status**: Architecture finalization  
**Timeline**: Q1-Q4 2026  
**Focus**: Design specs, prototypes, governance

See [Roadmap](roadmap/README.md)

---

## 🤝 Contributing

**Contribution Philosophy**:
- Design > Code (no PRs without RFCs)
- Registry rules are conservative
- Backward compatibility is sacred
- Security > Performance > UX

See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🛠️ Tech Stack

- **Core**: Rust (registry, verification)
- **Contracts**: Solidity (EVM compatibility)
- **Data**: Python (MRV analysis)
- **Docs**: Markdown → WebAssembly

---

## 📜 License

[MIT License](LICENSE) - Open, permissive, production-ready.

---

**Built for climate integrity** 🌍
