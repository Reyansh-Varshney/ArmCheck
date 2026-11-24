use std::process::ExitCode;

#[cfg(windows)]
pub(crate) fn run(json: bool) -> ExitCode {
    use armcheck_core::scan::scan_running;
    use std::io::{self, Write};

    let apps = match scan_running() {
        Ok(apps) => apps,
        Err(error) => {
            eprintln!("Could not scan running processes: {error}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        let mut output = io::stdout().lock();
        if let Err(error) = serde_json::to_writer_pretty(&mut output, &apps) {
            eprintln!("Could not write scan results: {error}");
            return ExitCode::FAILURE;
        }
        if let Err(error) = writeln!(output) {
            eprintln!("Could not finish scan output: {error}");
            return ExitCode::FAILURE;
        }
    } else {
        print_table(apps);
    }
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
pub(crate) fn run(_json: bool) -> ExitCode {
    eprintln!("Scanning running processes requires Windows.");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn print_table(apps: Vec<armcheck_core::model::App>) {
    use armcheck_core::model::{AppArchitecture, ProcessArchitecture};

    println!(
        "{:<36}  {:<16}  {:>9}  {:>9}  {:>12}",
        "App", "Architecture", "Processes", "CPU", "Working set"
    );
    for app in apps {
        let architecture = match app.architecture {
            AppArchitecture::NativeArm64 => "Native (ARM64)",
            AppArchitecture::Mixed => "Mixed",
            AppArchitecture::CouldNotVerify => "Couldn't verify",
            AppArchitecture::Emulated => {
                if app
                    .processes
                    .iter()
                    .all(|p| p.classification.architecture == ProcessArchitecture::EmulatedX64)
                {
                    "Emulated (x64)"
                } else if app
                    .processes
                    .iter()
                    .all(|p| p.classification.architecture == ProcessArchitecture::EmulatedX86)
                {
                    "Emulated (x86)"
                } else {
                    "Emulated"
                }
            }
        };
        let cpu = app
            .cpu_percent
            .map_or_else(|| "n/a".into(), |percent| format!("{percent:.2}%"));
        let ram = app.working_set_bytes.map_or_else(
            || "n/a".into(),
            |bytes| format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
        );
        println!(
            "{:<36.36}  {architecture:<16}  {:>9}  {cpu:>9}  {ram:>12}",
            app.name,
            app.processes.len()
        );
    }
}
