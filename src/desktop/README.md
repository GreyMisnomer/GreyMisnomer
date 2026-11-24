# GreyMisnomer Desktop Workbench & Sovereign Node (Tauri v2)

This package wraps the zero-cost client-side WebAssembly verification workbench (`docs/`) and bundles the native `greymisnomerd` daemon sidecar into a cross-platform desktop application (`.dmg`, `.msi`, `.AppImage`).

## Architecture (RFC-007 §7)

```
┌────────────────────────────────────────────────────────┐
│               GreyMisnomer Desktop App                 │
│                                                        │
│  ┌─────────────────────────┐  ┌─────────────────────┐  │
│  │   Tauri v2 WebView      │  │  greymisnomerd      │  │
│  │   (docs/ UI + WASM)     │◄─┼─ (Port 9482 RPC)    │  │
│  │   BigInt-safe Codecs    │  │  redb ACID Chain    │  │
│  └─────────────────────────┘  └──────────┬──────────┘  │
└──────────────────────────────────────────┼─────────────┘
                                           │
                         RFC 9162 Mirror ◄─┘
```

## Features
- **Zero-Terminal Experience**: Launches local sovereign daemon on unclaimed port `9482` automatically in OS app data directory.
- **Clean Lifecycle**: Automatically monitors child daemon process and tears down on window exit with zero orphaned background processes.
- **WASM Fallback**: Operates in standalone WebAssembly verification sandbox if daemon is offline or in read-only mode.
- **Native Packaging**: Bundles `.dmg` (macOS), `.msi` (Windows), and `.AppImage` (Linux) via GitHub Actions CI (`.github/workflows/release.yml`).

## Building

```bash
# Build desktop headless / sidecar runner
cargo build -p grey-misnomer-desktop

# Run desktop test suite
cargo test -p grey-misnomer-desktop
```

