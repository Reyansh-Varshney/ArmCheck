use std::{io, path::Path};

use super::*;

fn wow(process_machine: u16) -> Evidence {
    Evidence::IsWow64Process2 {
        process_machine,
        native_machine: COFF_MACHINE_ARM64,
    }
}

fn machine(machine: u16) -> Evidence {
    Evidence::ProcessMachineType {
        machine,
        machine_attributes: 0,
    }
}

#[test]
fn classifies_the_three_measured_runtime_combinations() {
    for (reported, typed, expected) in [
        (0, COFF_MACHINE_ARM64, ProcessArchitecture::NativeArm64),
        (0, COFF_MACHINE_X86_64, ProcessArchitecture::EmulatedX64),
        (
            COFF_MACHINE_X86,
            COFF_MACHINE_X86,
            ProcessArchitecture::EmulatedX86,
        ),
    ] {
        assert_eq!(
            classify(vec![wow(reported), machine(typed)], None).architecture,
            expected
        );
    }
}

#[test]
fn a_file_header_alone_does_not_resolve_the_ambiguous_runtime_query() {
    let file = Ok(FileCheck {
        architecture: FileArchitecture::X64,
        hybrid: false,
        evidence: vec![Evidence::PeHeader {
            machine: COFF_MACHINE_X86_64,
        }],
    });
    let result = classify(vec![wow(0)], Some(&file));
    assert_eq!(result.architecture, ProcessArchitecture::CouldNotVerify);
    assert_eq!(result.evidence.len(), 3);
    assert_eq!(
        result.verification_issue,
        Some(VerificationIssue::RuntimeUnverified)
    );
    assert_eq!(result.image_file_architecture, Some(FileArchitecture::X64));
}

#[test]
fn keeps_raw_evidence_when_a_runtime_and_file_result_disagree() {
    let file = Ok(FileCheck {
        architecture: FileArchitecture::Arm64,
        hybrid: false,
        evidence: vec![Evidence::PeHeader {
            machine: COFF_MACHINE_ARM64,
        }],
    });
    let result = classify(vec![wow(0), machine(COFF_MACHINE_X86_64)], Some(&file));
    assert_eq!(result.architecture, ProcessArchitecture::CouldNotVerify);
    assert_eq!(
        result.verification_issue,
        Some(VerificationIssue::ConflictingEvidence)
    );
    assert_eq!(
        result.image_file_architecture,
        Some(FileArchitecture::Arm64)
    );
    assert!(result.evidence.contains(&Evidence::PeHeader {
        machine: COFF_MACHINE_ARM64
    }));
    assert!(result.evidence.contains(&machine(COFF_MACHINE_X86_64)));
}

#[test]
fn rejects_conflicting_runtime_types_and_verified_hybrid_markers() {
    let conflict = classify(
        vec![wow(COFF_MACHINE_X86), machine(COFF_MACHINE_X86_64)],
        None,
    );
    assert_eq!(conflict.architecture, ProcessArchitecture::CouldNotVerify);
    assert_eq!(
        conflict.verification_issue,
        Some(VerificationIssue::ConflictingEvidence)
    );

    let hybrid = Ok(FileCheck {
        architecture: FileArchitecture::CouldNotVerify,
        hybrid: true,
        evidence: vec![
            Evidence::PeHeader {
                machine: COFF_MACHINE_ARM64,
            },
            explanation("Hybrid marker"),
        ],
    });
    let result = classify(vec![wow(0), machine(COFF_MACHINE_ARM64)], Some(&hybrid));
    assert_eq!(result.architecture, ProcessArchitecture::CouldNotVerify);
    assert!(result.evidence.contains(&explanation("Hybrid marker")));
    assert_eq!(
        result.verification_issue,
        Some(VerificationIssue::HybridExecutable)
    );
    assert_eq!(result.image_file_architecture, None);
}

#[test]
fn a_conclusive_runtime_result_can_survive_a_file_access_error() {
    let disk = Err(CheckFileError::Read {
        path: PathBuf::from("program.exe"),
        source: io::Error::from(io::ErrorKind::PermissionDenied),
    });
    let result = classify(vec![wow(0), machine(COFF_MACHINE_ARM64)], Some(&disk));
    assert_eq!(result.architecture, ProcessArchitecture::NativeArm64);
    assert!(
        matches!(result.evidence.last(), Some(Evidence::Explanation { message }) if message.contains("PE header unavailable"))
    );
}

#[test]
fn keeps_an_unopenable_process_and_its_win32_error() {
    let error = Evidence::Win32Error {
        operation: "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)".into(),
        code: 5,
    };
    let observation = Observation {
        pid: 4,
        name: "System".into(),
        image_path: None,
        timing: None,
        working_set_bytes: None,
        evidence: vec![error.clone()],
    };
    let rows = build_processes(vec![], vec![observation], 4);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pid, 4);
    assert_eq!(
        rows[0].classification.architecture,
        ProcessArchitecture::CouldNotVerify
    );
    assert!(rows[0].classification.evidence.contains(&error));
    assert_eq!(rows[0].cpu_percent, None);
    assert_eq!(rows[0].working_set_bytes, None);
}

fn timing(pid: u32, creation_time_100ns: u64, cpu_ticks_100ns: u64, sampled_at: Instant) -> Timing {
    Timing {
        identity: ProcessIdentity {
            pid,
            creation_time_100ns,
        },
        cpu_ticks_100ns,
        sampled_at,
        complete: true,
    }
}

#[test]
fn cpu_uses_total_capacity_and_requires_the_same_identity() {
    let now = Instant::now();
    let before = timing(42, 11, 2_000_000, now);
    let after = timing(42, 11, 4_500_000, now + Duration::from_millis(500));
    assert_eq!(cpu_percent(before, after, 4), Some(12.5));
    assert_eq!(
        cpu_percent(
            before,
            timing(42, 12, after.cpu_ticks_100ns, after.sampled_at),
            4
        ),
        None
    );
    assert_eq!(
        cpu_percent(
            before,
            timing(43, 11, after.cpu_ticks_100ns, after.sampled_at),
            4
        ),
        None
    );
    assert_eq!(cpu_percent(before, after, 0), None);
}

fn observation(timing: Timing) -> Observation {
    Observation {
        pid: timing.identity.pid,
        name: "fixture.exe".into(),
        image_path: None,
        timing: Some(timing),
        working_set_bytes: Some(64),
        evidence: vec![wow(0), machine(COFF_MACHINE_ARM64)],
    }
}

#[test]
fn keeps_reused_pids_separate_and_leaves_unmatched_measurements_unavailable() {
    let now = Instant::now();
    let after = now + Duration::from_millis(500);
    let first = vec![
        observation(timing(42, 11, 0, now)),
        observation(timing(23, 12, 0, now)),
        observation(timing(51, 13, 0, now)),
    ];
    let second = vec![
        observation(timing(42, 14, 2_500_000, after)),
        observation(timing(33, 15, 2_500_000, after)),
        observation(timing(51, 13, 2_500_000, after)),
    ];
    let processes = build_processes(first, second, 4);
    let reused: Vec<_> = processes
        .iter()
        .filter(|process| process.pid == 42)
        .collect();
    assert_eq!(reused.len(), 2);
    assert_ne!(reused[0].creation_time_100ns, reused[1].creation_time_100ns);
    for process in &processes {
        if process.pid == 51 {
            assert_eq!(process.cpu_percent, Some(12.5));
            assert_eq!(process.working_set_bytes, Some(64));
        } else {
            assert_eq!(process.cpu_percent, None);
            assert_eq!(process.working_set_bytes, None);
        }
    }
    assert_eq!(processes.len(), 5);
}

fn process(pid: u32, path: Option<&str>, architecture: ProcessArchitecture) -> Process {
    Process {
        pid,
        name: "fixture.exe".into(),
        creation_time_100ns: Some(1),
        image_path: path.map(PathBuf::from),
        cpu_percent: Some(1.0),
        working_set_bytes: Some(64),
        classification: ProcessClassification {
            architecture,
            verification_issue: None,
            image_file_architecture: None,
            evidence: vec![],
        },
    }
}

#[test]
fn groups_exact_paths_and_marks_verified_native_and_emulated_children_mixed() {
    let first = process(1, Some(r"C:\Tool\a.exe"), ProcessArchitecture::NativeArm64);
    let second = process(2, Some(r"C:\Tool\a.exe"), ProcessArchitecture::EmulatedX64);
    let mut unknown = process(
        3,
        Some(r"C:\Tool\a.exe"),
        ProcessArchitecture::CouldNotVerify,
    );
    unknown.cpu_percent = None;
    let apps = group_apps(
        vec![first, second, unknown],
        Some(Path::new(r"C:\Windows")),
        |_| None,
    );
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].architecture, AppArchitecture::Mixed);
    assert_eq!(apps[0].processes.len(), 3);
    assert_eq!(apps[0].cpu_percent, None);
    assert_eq!(apps[0].working_set_bytes, Some(192));
    assert!(matches!(
        apps[0].grouping,
        Some(GroupingEvidence::ExecutablePath { .. })
    ));
}

#[test]
fn a_native_and_unverified_group_remains_unverified() {
    let first = process(1, Some(r"C:\Tool\a.exe"), ProcessArchitecture::NativeArm64);
    let second = process(
        2,
        Some(r"C:\Tool\a.exe"),
        ProcessArchitecture::CouldNotVerify,
    );
    let apps = group_apps(vec![first, second], Some(Path::new(r"C:\Windows")), |_| {
        None
    });
    assert_eq!(apps[0].architecture, AppArchitecture::CouldNotVerify);
}

fn shared_product(_: &Path) -> Option<ProductVersion> {
    Some(ProductVersion {
        company: "Example Company".into(),
        product: "Example Tool".into(),
    })
}

#[test]
fn groups_product_metadata_only_with_a_corroborating_install_directory() {
    let rows = vec![
        process(1, Some(r"C:\Tool\a.exe"), ProcessArchitecture::NativeArm64),
        process(2, Some(r"C:\Tool\b.exe"), ProcessArchitecture::NativeArm64),
        process(3, Some(r"C:\Other\c.exe"), ProcessArchitecture::NativeArm64),
        process(4, None, ProcessArchitecture::CouldNotVerify),
        process(5, None, ProcessArchitecture::CouldNotVerify),
        process(
            6,
            Some(r"C:\WINDOWS\System32\x.exe"),
            ProcessArchitecture::NativeArm64,
        ),
        process(
            7,
            Some(r"C:\WINDOWS\System32\y.exe"),
            ProcessArchitecture::NativeArm64,
        ),
    ];

    let apps = group_apps(rows, Some(Path::new(r"C:\Windows")), shared_product);
    assert_eq!(apps.len(), 6);
    let merged = apps
        .iter()
        .find(|row| row.processes.len() == 2)
        .expect("expected a corroborated product group");
    assert_eq!(merged.name, "Example Tool");
    assert_eq!(
        merged
            .processes
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(matches!(
        merged.grouping,
        Some(GroupingEvidence::ProductVersion { .. })
    ));
}

#[test]
fn suppresses_both_metrics_for_a_matching_identity_with_an_incomplete_sample() {
    let now = Instant::now();
    let mut early = timing(10, 1, 2_000_000, now);
    early.complete = false;
    let late = timing(10, 1, 4_000_000, now + Duration::from_millis(500));
    let processes = build_processes(vec![observation(early)], vec![observation(late)], 4);
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0].cpu_percent, None);
    assert_eq!(processes[0].working_set_bytes, None);
}
