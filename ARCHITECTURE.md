# ArmCheck architecture

`armcheck-core` owns the data model, file inspection, and Windows process scanning. `armcheck-cli` provides terminal input and output. The Tauri app in `app/src-tauri` calls the core library and hosts the React frontend in WebView2. All three crates build for `aarch64-pc-windows-msvc` by default.

## File and process results

`FileCheck` reports findings about an executable on disk. The PE reader seeks to the required header and metadata ranges and reads at most 1 MiB per file. ARM64EC and ARM64X machine codes and hybrid markers yield **Couldn't verify**. The evidence preserves the raw machine code and any marker found.

`ProcessClassification` describes a running process. ArmCheck opens each enumerated PID with `PROCESS_QUERY_LIMITED_INFORMATION`. If that fails, the scanner retains the PID, records the Win32 error, and reports **Couldn't verify**.

Controlled process probes on Windows 11 ARM64 returned these values:

| Executable verified by Dumpbin | IsWow64Process2 process machine | IsWow64Process2 native machine | ProcessMachineTypeInfo machine |
| --- | --- | --- | --- |
| ARM64 | `0x0000` | `0xAA64` | `0xAA64` |
| x64 | `0x0000` | `0xAA64` | `0x8664` |
| x86 | `0x014C` | `0xAA64` | `0x014C` |

`IsWow64Process2` alone can leave ARM64 and x64 ambiguous. ArmCheck retains the runtime results and uses `GetProcessInformation(ProcessMachineTypeInfo)` to resolve that ambiguity. A mismatch between conclusive observations or a hybrid marker produces **Couldn't verify**. If the file is unavailable, a conclusive runtime result can support a label with evidence about the unavailable file. Each image path is checked once per scan. A separately labeled file architecture provides a disk-only observation when the running architecture remains uncertain.

## Running app rows and desktop scope

An `App` groups processes that share an exact executable path. Different executable paths may share a row when their version resources give the same product and company and the files share an install directory outside the Windows system directory. Processes without a reliable match get their own rows. A group with verified native and verified emulated children is **Mixed**. **Native** and **Emulated** require all children to be verified and agree at that level. Other groups are **Couldn't verify**.

**Desktop apps** limits the view to groups with evidence of a visible, titled, non-tool top-level window on the current desktop, including minimized windows that retain their visible style. The window scan ignores cloaked surfaces. **All processes** retains rows without qualifying windows or process access. The desktop scope uses window ownership as evidence and can miss an app when a separate process owns its window. The reason breakdown counts app rows in the selected scope. A grouped row can contribute to multiple reasons when its children have different evidence.

The CLI's `scan` lists running apps. `scan --json` includes process measurements, architecture evidence, and the basis for grouping.

## CPU and working set

Each scan takes two snapshots with a 300 ms pause. CPU is `100 × Δ(kernel time + user time) ÷ (elapsed time × active logical processors)`. The numerator and denominator use seconds. Elapsed time is measured between the two timing reads for each process. RAM is the working set read during the second snapshot.

A sample pair must match on PID and process creation time. A process that starts or exits during the window remains visible with both CPU and RAM unavailable. A group displays a total for a metric when all its child measurements for that metric are available. Summed working sets can include pages shared by multiple processes.

## Desktop refresh

React schedules the next scan after the previous scan completes. The Rust command checks that the native window is visible and unminimized before collecting a snapshot, during the sampling pause, and before reading the results. Restoring the window resumes scanning. The desktop layer caches Windows icons extracted from image paths.
