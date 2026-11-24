# ArmCheck architecture

`armcheck-core` owns the data model and file inspection. It will also handle process scanning. `armcheck-cli` depends on it and handles terminal input and output. The Tauri app will also call the core library when it joins the workspace in Milestone 3. Both current crates build for `aarch64-pc-windows-msvc` by default.

## File and process results

`FileCheck` describes the machine type declared by an executable's PE header. `ProcessClassification` describes how a running process is executing. Both carry `Evidence` with the observations used to produce the result. Installed copies and available native releases will have separate records when those features are added.

When a conclusive `IsWow64Process2` result and a readable PE header identify different architectures, the process is **Couldn't verify**. Keep the raw values from both sources and explain the disagreement. If the header is unavailable, a conclusive runtime result can support a label with evidence that the header check was unavailable. If the runtime query is inconclusive or fails, a file header by itself does not establish how the process is running.

The file checker reports **Couldn't verify** for ARM64EC and ARM64X machine codes and for hybrid markers in the PE load configuration. Some linked hybrid images carry an ordinary ARM64 or x64 machine code, so the result includes both the raw code and the hybrid evidence. Revisit fuller handling for these formats after V1.

Run the file check with `cargo run -p armcheck-cli -- check "<path-to-exe>"`. A readable file with uncertain architecture returns an evidence trail. Invalid inputs, such as a missing file or truncated PE header, produce an error and exit with code 1.

Before implementing the runtime rules, verify the API's actual output on the ARM64 laptop for native ARM64 and emulated x64 and x86 processes.

## Running app rows

An `App` groups related running `Process` records and keeps their evidence available. A group is **Mixed** as soon as it contains a verified native process and a verified emulated process. A group is **Native** or **Emulated** if all child processes are verified and agree at that level. A group whose verified processes are all emulated can include both x64 and x86 processes. Other groups are **Couldn't verify**.

CPU represents a percentage of total CPU capacity over the sampling window. RAM is working set in bytes. An app-level metric is unavailable when its child measurements are incomplete.
