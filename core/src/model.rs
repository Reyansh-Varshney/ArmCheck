use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum FileArchitecture {
    Arm64,
    X64,
    X86,
    CouldNotVerify,
}

/// A file's architecture result and the PE observations behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileCheck {
    pub architecture: FileArchitecture,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessArchitecture {
    NativeArm64,
    EmulatedX64,
    EmulatedX86,
    CouldNotVerify,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    PeHeader {
        machine: u16,
    },
    IsWow64Process2 {
        process_machine: u16,
        native_machine: u16,
    },
    Explanation {
        message: String,
    },
}

/// A running process's architecture and the observations behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessClassification {
    pub architecture: ProcessArchitecture,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    pub pid: u32,
    pub image_path: Option<PathBuf>,
    pub classification: ProcessClassification,
    // Percent of total CPU capacity over the sample window.
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppArchitecture {
    NativeArm64,
    Emulated,
    Mixed,
    CouldNotVerify,
}

/// A running app row. Its child processes carry the architecture evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct App {
    pub name: String,
    pub architecture: AppArchitecture,
    pub processes: Vec<Process>,
    // None means the row has no complete measurement for this metric.
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
}
