# ArmCheck architecture

`armcheck-core` owns the data model, file inspection, and Windows process scanning. `armcheck-cli` provides terminal input and output. The Tauri app in app/src-tauri calls the core library and hosts a React frontend in WebView2. All three crates build for `aarch64-pc-windows-msvc` by default.

## File and process results

`FileCheck` reports findings about an executable on disk. The PE reader seeks to the required header and metadata ranges and reads at most 1 MiB per file. ARM64EC and ARM64X machine codes and hybrid markers yield **Couldn't verify**. The evidence preserves the raw machine code and the marker. Revisit fuller handling for these formats after V1.

Run `cargo run -p armcheck-cli -- check "<path-to-exe>"` for a file check. Invalid inputs, such as a missing file or a truncated PE header, produce an error and exit with code 1.

`ProcessClassification` describes a running process. ArmCheck opens each enumerated PID with `PROCESS_QUERY_LIMITED_INFORMATION`. If that fails, it retains the process, records the Win32 error, and reports **Couldn't verify**.

On the ARM64 laptop the controlled process probes produced these values. Both APIs succeeded for all three processes.

| Executable verified by Dumpbin | IsWow64Process2 process machine | IsWow64Process2 native machine | ProcessMachineTypeInfo machine |
| --- | --- | --- | --- |
| ARM64 | `0x0000` | `0xAA64` | `0xAA64` |
| x64 | `0x0000` | `0xAA64` | `0x8664` |
| x86 | `0x014C` | `0xAA64` | `0x014C` |

`IsWow64Process2` alone leaves ARM64 and x64 ambiguous on this machine. ArmCheck retains both queries' raw results and uses `GetProcessInformation(ProcessMachineTypeInfo)` to resolve that ambiguity. A readable, conclusive PE header should agree with the runtime result. A disagreement or hybrid marker produces **Couldn't verify**. If the file is unavailable, a conclusive runtime result can support a label with evidence about the unavailable file. Each image path is checked once per scan. Installed copies and available native releases will have separate records when those features are added.

## Running app rows

Run `cargo run -p armcheck-cli -- scan` for the table or add `--json` for process measurements, architecture evidence, and the basis for grouping.

An `App` groups processes that share an exact executable path. Different executable paths may share a row when their version resources give the same product and company and the files share an install directory outside the Windows system directory. Processes without a reliable match get their own rows. A group with verified native and verified emulated children is **Mixed**. **Native** and **Emulated** require all children to be verified and agree at that level. Other groups are **Couldn't verify**.

## CPU and working set

Each CLI scan takes two snapshots with a 300 ms pause. CPU is `100 × Δ(kernel time + user time) ÷ (elapsed time × active logical processors)`. The numerator and denominator use seconds. Elapsed time is measured between the two timing reads for each process. RAM is the working set read during the second snapshot.

A sample pair must match on PID and process creation time. A process that starts or exits during the window remains visible with both CPU and RAM unavailable. A group displays a total for a metric when all its child measurements for that metric are available.

## Desktop refresh

React schedules a scan after the previous scan completes. The Rust command verifies that the native window is visible and unminimized before collecting a snapshot, during the sampling pause, and before reading the results. The next scan starts when the window becomes visible again. The desktop layer caches the Windows icons it extracts from process image paths for the running-app list.
