# Contributing to ArmCheck

## Report an issue

Include the ArmCheck version, the Windows 11 build number, and steps to reproduce the problem. For an architecture discrepancy, include the relevant machine codes or Win32 error shown under **Technical details**. Share a small excerpt that omits usernames, unrelated process details, and private paths.

## Check a change locally

Use a Windows 11 ARM64 development machine with the tools listed in the [README](README.md#build-from-source). From the repository root:

```powershell
npm --prefix app ci
npm --prefix app run build
cargo fmt --all --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Test UI changes in the native app. Minimize and restore the window if a change affects refresh, and check both app scopes if it affects grouping. Changes to detection should preserve the original observations and include a reproducible test where practical.

## Prepare release artifacts

The [Windows ARM64 workflow](.github/workflows/arm64.yml) validates pull requests and pushes to `main`. Manually running the workflow or pushing a version tag also builds the installer, checks the app's PE machine field, and uploads the executable, installer, and checksum file as a workflow artifact.

Before publishing, use a matching app version and Git tag, review [the changelog](CHANGELOG.md), and run a smoke test on Windows ARM64. Attach the reviewed artifacts and checksums to the matching GitHub Release.
