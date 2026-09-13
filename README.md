<div align="center">
  <h1>🌍 GreyMisnomer</h1>
  <p><b>A zero-trust, immutably-auditable carbon credit registry running entirely in the browser.</b></p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Status](https://img.shields.io/badge/Status-Alpha-orange)]()
</div>

Like Bitcoin Core, but for carbon credits. GreyMisnomer solves the opacity and double-counting issues in voluntary carbon markets by moving the core registry logic—including Merkle proofs, invariants, and credit batching—into a cryptographically verifiable WebAssembly module.

**Not a marketplace. A settlement layer.**

---

## ⚡ Try it Live
**[Open the Interactive Simulator](https://greymisnomer.github.io/GreyMisnomer/)**

The entire 7-step protocol (MRV data upload → Merkle Commitment → Minting → Transfer → Partial Retirement → Audit Export) is available to test directly in your browser. **No backend or database is required.**

---

## 📋 Table of Contents
- [Vision](#-vision)
- [Architecture](#-architecture)
- [Invariants Enforced](#-invariants-enforced)
- [Project Structure](#-project-structure)
- [Getting Started (Local Development)](#-getting-started-local-development)
- [Documentation & Links](#-documentation--links)
- [Tech Stack](#-tech-stack)
- [Contributing](#-contributing)
- [License](#-license)

---

## 👁️ Vision

Build **registry-first infrastructure** for carbon markets where:
- **Registry > Market**: Separation of credit legitimacy from price discovery
- **Proof-of-Integrity (PoI)**: Cryptographic proof before minting
- **Proof-of-Offset (PoO)**: Irreversible consumption receipt
- **Serialization**: Every credit uniquely tracked

---

## 🏗️ Architecture

GreyMisnomer moves the state machine out of a trusted backend and into the client browser:

`mermaid
graph LR
    A[Rust Protocol Core] -->|wasm-pack| B(WebAssembly Module)
    B -->|Loaded by| C[app.html Simulator]
    C -->|Generates| D[ZIP Audit Artifacts]
    C -->|Verifies| E[Merkle Proofs]
`

1. **Rust Library (grey-misnomer-core)**: Implements the strict RFC invariants, BLAKE3 hashing, and supply arithmetic.
2. **WASM Bindings (grey-misnomer-wasm)**: Exposes the Rust state machine to JavaScript.
3. **Web Interface (docs/app.html)**: A 100% client-side simulator where project developers can walk through the lifecycle of a carbon credit and export their cryptographic proofs as JSON/PDF artifacts.

---

## 🛡️ Invariants Enforced

The WASM core mathematically prevents:
- **Replay attacks**: A Proof-of-Integrity (PoI) can only be minted into credits exactly once.
- **Supply inflation**: Minted amounts must exactly match the length of the serial number range.
- **Double spending**: Credit transfers and retirements track precise serial slices; you cannot transfer overlapping ranges.
- **Tampering**: All MRV (Measurement, Reporting, and Verification) sensor data is committed to a BLAKE3 Merkle tree before minting.

---

## 📁 Project Structure

- src/ — Rust protocol core (grey-misnomer-core) and WASM bindings (grey-misnomer-wasm).
- docs/ — The static WebAssembly front-end and interactive simulator.
- rchitecture/ — System architecture diagrams and design documents.
- esearch/ — Papers, references, standards, and specifications.
- governance/ — Voluntary market rules, standards, and policy definitions.
- deployments/ — Infrastructure deployment scripts.
- poc/ — Experimental proof-of-concept implementations.
- 	ests/ — Integration and unit tests for the core registry logic.
- oadmap/ — Future project milestones and features.

---

## 🚀 Getting Started (Local Development)

If you want to run the simulator locally and compile the Rust protocol yourself:

### Prerequisites
- Rust (ustup default stable)
- wasm32-unknown-unknown target (ustup target add wasm32-unknown-unknown)
- wasm-pack
- Node.js (for http-server)

### 1. Clone the repository
\\\ash
git clone https://github.com/GreyMisnomer/GreyMisnomer.git
cd GreyMisnomer
\\\

### 2. Build the WASM module
\\\ash
cd src/wasm
wasm-pack build --target web --out-dir ../../docs/pkg --out-name grey_misnomer_wasm
\\\

### 3. Serve the web app
\\\ash
cd ../../docs
npx -y http-server -p 8080 --cors -c-1
\\\
Open http://localhost:8080/app.html in your browser.

---

## 📚 Documentation & Links

- **Website/Simulator**: https://greymisnomer.github.io/GreyMisnomer/
- **Discord**: https://discord.gg/CZXXPJUNM
- **Reddit**: https://reddit.com/r/GreyMisnomer
- **Whitepaper**: [Design Document](architecture/design_document_v2.pdf)
- **Q&A**: [Questions & Answers](architecture/qna_document_v1.pdf)
- **Diagrams**: [System Architecture](architecture/diagrams/)

---

## 🛠️ Tech Stack

- **Core Protocol**: Rust
- **Web Runtime**: WebAssembly (WASM)
- **Client Application**: Vanilla JavaScript, HTML5, CSS3

---

## 🤝 Contributing

**Contribution Philosophy**:
- Design > Code (no PRs without RFCs)
- Registry rules are conservative
- Backward compatibility is sacred
- Security > Performance > UX

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

---

## 📄 License

[MIT License](LICENSE) - Open, permissive, production-ready.

---

**Built for climate integrity** 🌱
