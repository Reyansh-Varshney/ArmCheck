use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileArchitecture {
    Arm64,
    X64,
    X86,
    ManagedAnyCpu,
    CouldNotVerify,
}

/// A file's architecture result and the PE observations behind it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileCheck {
    pub architecture: FileArchitecture,
    #[serde(skip)]
    pub(crate) hybrid: bool,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessArchitecture {
    NativeArm64,
    EmulatedX64,
    EmulatedX86,
    CouldNotVerify,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    PeHeader {
        machine: u16,
    },
    IsWow64Process2 {
        process_machine: u16,
        native_machine: u16,
    },
    ProcessMachineType {
        machine: u16,
        machine_attributes: u32,
    },
    Win32Error {
        operation: String,
        code: u32,
    },
    Explanation {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationIssue {
    AccessDenied,
    ProcessUnavailable,
    HybridExecutable,
    ConflictingEvidence,
    FileUnverified,
    RuntimeUnverified,
}

/// A running process's architecture and the observations behind it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessClassification {
    pub architecture: ProcessArchitecture,
    pub verification_issue: Option<VerificationIssue>,
    pub image_file_architecture: Option<FileArchitecture>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub creation_time_100ns: Option<u64>,
    pub image_path: Option<PathBuf>,
    pub classification: ProcessClassification,
    // Percent of total CPU capacity over the sample window.
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppArchitecture {
    NativeArm64,
    Emulated,
    Mixed,
    CouldNotVerify,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupingEvidence {
    ExecutablePath {
        path: PathBuf,
    },
    ProductVersion {
        directory: PathBuf,
        product: String,
        company: String,
    },
}

/// A running app row. Its child processes carry the architecture evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct App {
    pub name: String,
    pub architecture: AppArchitecture,
    pub grouping: Option<GroupingEvidence>,
    pub processes: Vec<Process>,
    // None means the row has no complete measurement for this metric.
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
}
