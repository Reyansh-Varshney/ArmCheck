use std::{env, ffi::OsStr, path::Path, process::ExitCode};

use armcheck_core::{
    file_check::check_file,
    model::{Evidence, FileArchitecture},
};

mod scan;

const USAGE: &str = "Usage: armcheck-cli check <path-to-exe>\n       armcheck-cli scan [--json]";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let command = args.next();
    let path = args.next();
    match (
        command.as_deref().and_then(OsStr::to_str),
        path,
        args.next(),
    ) {
        (Some("check"), Some(path), None) => check(Path::new(&path)),
        (Some("scan"), None, None) => scan::run(false),
        (Some("scan"), Some(flag), None) if flag == "--json" => scan::run(true),
        (Some("-h" | "--help"), None, None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check(path: &Path) -> ExitCode {
    let result = match check_file(path) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Couldn't verify: {error}");
            return ExitCode::FAILURE;
        }
    };

    let label = match result.architecture {
        FileArchitecture::Arm64 => "Native (ARM64)",
        FileArchitecture::X64 => "x64",
        FileArchitecture::X86 => "x86",
        FileArchitecture::ManagedAnyCpu => "AnyCPU (.NET)",
        FileArchitecture::CouldNotVerify => "Couldn't verify",
    };
    println!("{label}");
    for evidence in result.evidence {
        match evidence {
            Evidence::PeHeader { machine } => println!("PE header machine = 0x{machine:04X}"),
            Evidence::Explanation { message } => println!("{message}"),
            Evidence::ProcessMachineType {
                machine,
                machine_attributes,
            } => {
                println!(
                    "Process machine = 0x{machine:04X}, attributes = 0x{machine_attributes:08X}"
                );
            }
            Evidence::Win32Error { operation, code } => {
                println!("{operation} failed (Win32 error {code})")
            }
            Evidence::IsWow64Process2 {
                process_machine,
                native_machine,
            } => {
                println!(
                    "Process machine = 0x{process_machine:04X}, host machine = 0x{native_machine:04X}"
                );
            }
        }
    }

    ExitCode::SUCCESS
}
