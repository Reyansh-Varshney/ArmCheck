# ArmCheck

ArmCheck is a Windows 11 on ARM utility for checking whether running apps are native or emulated and inspecting the architecture of an executable on disk.

## Prerequisites

- Windows 11 on ARM with the WebView2 Runtime
- Rust with the `aarch64-pc-windows-msvc` toolchain, rustfmt, and Clippy
- Visual Studio Build Tools with the ARM64 C++ tools and Windows SDK
- Node.js and npm for the Tauri frontend

## Run the desktop app

From the repository root in PowerShell:

```powershell
Set-Location app
npm ci
npm run tauri -- dev
```

The home screen shows grouped running apps. Search, filter by architecture, sort by name, CPU, or RAM, or turn on **Technical details** to inspect the evidence. The **Check a file** area accepts an executable or installer by drop or file picker. An installer's architecture can differ from the app it installs.

Minimize to pause live scans. Closing the window hides ArmCheck to the notification area, where **Show ArmCheck** restores it and **Quit ArmCheck** exits.

## Build a native release

From `app`, run:

```powershell
npm ci
npm run tauri -- build --target aarch64-pc-windows-msvc
```

The native executable is at `target/aarch64-pc-windows-msvc/release/armcheck.exe` under the repository root. The NSIS installer is under `target/aarch64-pc-windows-msvc/release/bundle/nsis/`. Add `--no-bundle` for the standalone executable.

## CLI and tests

From the root:

```powershell
cargo run -p armcheck-cli -- scan
cargo run -p armcheck-cli -- scan --json
cargo run -p armcheck-cli -- check "C:\path\to\app.exe"
cargo test -p armcheck-core -p armcheck-cli
```

To check the entire workspace, build the frontend with `npm --prefix app run build` after installing dependencies, then run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all --check`.

See [the architecture notes](ARCHITECTURE.md) for the measurement and classification rules.
