use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf, Prefix},
    thread,
    time::{Duration, Instant},
};

use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use thiserror::Error;

use crate::{
    file_check::{CheckFileError, check_file},
    model::{
        App, AppArchitecture, Evidence, FileArchitecture, FileCheck, GroupingEvidence, Process,
        ProcessArchitecture, ProcessClassification,
    },
};

mod version;
mod windows;

const SAMPLE_PAUSE: Duration = Duration::from_millis(300);

#[derive(Debug, Error)]
#[error("{operation}: {source}")]
pub struct ScanError {
    operation: &'static str,
    source: ::windows::core::Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    creation_time_100ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct Timing {
    identity: ProcessIdentity,
    cpu_ticks_100ns: u64,
    sampled_at: Instant,
    complete: bool,
}

struct Observation {
    pid: u32,
    name: String,
    image_path: Option<PathBuf>,
    timing: Option<Timing>,
    working_set_bytes: Option<u64>,
    evidence: Vec<Evidence>,
}

pub fn scan_running() -> Result<Vec<App>, ScanError> {
    Ok(scan_running_while(|| true)?.unwrap_or_default())
}

/// Checks whether the caller still wants a scan before each snapshot and between sampling ticks.
pub fn scan_running_while(still_needed: impl Fn() -> bool) -> Result<Option<Vec<App>>, ScanError> {
    if !still_needed() {
        return Ok(None);
    }
    let logical_processors = windows::active_processor_count();
    let first = windows::snapshot(false)?;
    let sampling_started = Instant::now();
    while let Some(remaining) = SAMPLE_PAUSE.checked_sub(sampling_started.elapsed()) {
        if !still_needed() {
            return Ok(None);
        }
        thread::sleep(remaining.min(Duration::from_millis(60)));
    }
    if !still_needed() {
        return Ok(None);
    }
    let second = windows::snapshot(true)?;
    if !still_needed() {
        return Ok(None);
    }
    let windows_directory = windows::windows_directory();
    Ok(Some(group_apps(
        build_processes(first, second, logical_processors),
        windows_directory.as_deref(),
        version::product_version,
    )))
}

fn build_processes(
    first: Vec<Observation>,
    second: Vec<Observation>,
    logical_processors: u32,
) -> Vec<Process> {
    let mut before: HashMap<_, _> = first.into_iter().map(|entry| (entry.pid, entry)).collect();
    let mut image_checks = HashMap::new();
    let mut processes = Vec::with_capacity(second.len());

    for mut current in second {
        let previous = before.remove(&current.pid);
        let earlier = previous.as_ref().and_then(|entry| entry.timing);
        let timings = earlier.zip(current.timing);
        let matched = timings.filter(|(start, end)| start.identity == end.identity);

        if timings.is_some()
            && matched.is_none()
            && let Some(previous) = previous
        {
            processes.push(unavailable_process(
                previous,
                "This process exited during sampling",
                &mut image_checks,
            ));
        }
        if !matched.is_some_and(|(start, end)| start.complete && end.complete) {
            processes.push(unavailable_process(
                current,
                "CPU and RAM require this process to be available in both samples",
                &mut image_checks,
            ));
            continue;
        }

        let cpu = matched.and_then(|(start, end)| cpu_percent(start, end, logical_processors));
        if cpu.is_none() {
            current
                .evidence
                .push(explanation("CPU timing was unavailable"));
        }
        processes.push(process_from_observation(current, cpu, &mut image_checks));
    }

    for previous in before.into_values() {
        processes.push(unavailable_process(
            previous,
            "This process exited during sampling",
            &mut image_checks,
        ));
    }
    processes
}

fn cpu_percent(start: Timing, end: Timing, logical_processors: u32) -> Option<f64> {
    if start.identity != end.identity || !start.complete || !end.complete || logical_processors == 0
    {
        return None;
    }
    let seconds = end
        .sampled_at
        .checked_duration_since(start.sampled_at)?
        .as_secs_f64();
    if seconds == 0.0 {
        return None;
    }
    // One CPU tick is 100 ns. Divide by the elapsed capacity of all logical processors.
    let ticks = end.cpu_ticks_100ns.checked_sub(start.cpu_ticks_100ns)?;
    Some(100.0 * (ticks as f64 / 10_000_000.0) / (seconds * f64::from(logical_processors)))
}

fn unavailable_process(
    mut entry: Observation,
    reason: &'static str,
    image_checks: &mut HashMap<PathBuf, Result<FileCheck, CheckFileError>>,
) -> Process {
    entry.working_set_bytes = None;
    entry.evidence.push(explanation(reason));
    process_from_observation(entry, None, image_checks)
}

fn process_from_observation(
    entry: Observation,
    cpu_percent: Option<f64>,
    image_checks: &mut HashMap<PathBuf, Result<FileCheck, CheckFileError>>,
) -> Process {
    // Multi-process apps commonly share an image. Read its PE data once per scan.
    let image_check = entry.image_path.as_ref().map(|path| {
        &*image_checks
            .entry(path.clone())
            .or_insert_with(|| check_file(path))
    });
    Process {
        pid: entry.pid,
        name: entry.name,
        creation_time_100ns: entry
            .timing
            .map(|timing| timing.identity.creation_time_100ns),
        image_path: entry.image_path,
        classification: classify(entry.evidence, image_check),
        cpu_percent,
        working_set_bytes: entry.working_set_bytes,
    }
}

fn classify(
    mut evidence: Vec<Evidence>,
    image: Option<&Result<FileCheck, CheckFileError>>,
) -> ProcessClassification {
    let mut architecture = match runtime_architecture(&evidence) {
        Ok(architecture) => architecture,
        Err(reason) => {
            evidence.push(explanation(reason));
            ProcessArchitecture::CouldNotVerify
        }
    };
    match image {
        Some(Ok(file)) => {
            evidence.extend(file.evidence.iter().cloned());
            match file.architecture {
                FileArchitecture::CouldNotVerify => {
                    architecture = ProcessArchitecture::CouldNotVerify
                }
                _ if architecture != ProcessArchitecture::CouldNotVerify
                    && !disk_matches_runtime(&file.architecture, &architecture) =>
                {
                    evidence.push(explanation(
                        "Runtime architecture disagrees with the executable's PE header",
                    ));
                    architecture = ProcessArchitecture::CouldNotVerify;
                }
                _ => {}
            }
        }
        Some(Err(
            error @ (CheckFileError::Missing { .. }
            | CheckFileError::NotFile { .. }
            | CheckFileError::Read { .. }),
        )) => {
            evidence.push(explanation(format!("PE header unavailable: {error}")));
        }
        Some(Err(error)) => {
            evidence.push(explanation(format!(
                "PE header could not be verified: {error}"
            )));
            architecture = ProcessArchitecture::CouldNotVerify;
        }
        None => {}
    }

    ProcessClassification {
        architecture,
        evidence,
    }
}

fn runtime_architecture(evidence: &[Evidence]) -> Result<ProcessArchitecture, &'static str> {
    let (process_machine, native_machine) = evidence
        .iter()
        .find_map(|item| match item {
            Evidence::IsWow64Process2 {
                process_machine,
                native_machine,
            } => Some((*process_machine, *native_machine)),
            _ => None,
        })
        .ok_or("IsWow64Process2 did not provide a runtime architecture")?;
    if native_machine != COFF_MACHINE_ARM64 {
        return Err("IsWow64Process2 did not report an ARM64 host");
    }
    let machine_type = evidence.iter().find_map(|item| match item {
        Evidence::ProcessMachineType { machine, .. } => Some(*machine),
        _ => None,
    });

    // On this ARM64 build, IsWow64Process2 returned zero for native ARM64 and emulated x64.
    // ProcessMachineTypeInfo distinguished the two while the fixtures were running.
    match (process_machine, machine_type) {
        (0, Some(COFF_MACHINE_ARM64)) => Ok(ProcessArchitecture::NativeArm64),
        (0, Some(COFF_MACHINE_X86_64)) => Ok(ProcessArchitecture::EmulatedX64),
        (COFF_MACHINE_X86, None | Some(COFF_MACHINE_X86)) => Ok(ProcessArchitecture::EmulatedX86),
        (COFF_MACHINE_X86_64, Some(COFF_MACHINE_X86_64)) => Ok(ProcessArchitecture::EmulatedX64),
        (0xA641 | 0xA64E, _) | (_, Some(0xA641 | 0xA64E)) => {
            Err("The runtime query reported ARM64EC or ARM64X")
        }
        (0, None) => Err("IsWow64Process2 could not distinguish ARM64 from x64"),
        (0, Some(_)) => Err("The runtime queries gave an unverified machine type"),
        (_, Some(other)) if other != process_machine => {
            Err("The two runtime architecture queries disagree")
        }
        _ => Err("The runtime queries did not verify a supported architecture"),
    }
}

fn disk_matches_runtime(file: &FileArchitecture, runtime: &ProcessArchitecture) -> bool {
    matches!(
        (file, runtime),
        (FileArchitecture::Arm64, ProcessArchitecture::NativeArm64)
            | (FileArchitecture::X64, ProcessArchitecture::EmulatedX64)
            | (FileArchitecture::X86, ProcessArchitecture::EmulatedX86)
    )
}

#[derive(Debug)]
struct ProductVersion {
    product: String,
    company: String,
}

fn group_apps(
    processes: Vec<Process>,
    windows_directory: Option<&Path>,
    mut read_product: impl FnMut(&Path) -> Option<ProductVersion>,
) -> Vec<App> {
    let mut by_identity: HashMap<GroupingEvidence, usize> = HashMap::new();
    let mut product_cache = HashMap::new();
    let mut groups: Vec<(Option<GroupingEvidence>, Vec<Process>)> = Vec::new();

    for process in processes {
        let grouping = process.image_path.as_ref().map(|path| {
            // Product metadata can be generic. Corroborate it with publisher
            // and directory, and use exact paths for Windows system images.
            if let Some(directory) = path.parent().filter(|directory| {
                windows_directory.is_some_and(|system_root| outside_windows(directory, system_root))
            }) {
                let product = product_cache
                    .entry(path.clone())
                    .or_insert_with(|| read_product(path));
                if let Some(product) = product {
                    return GroupingEvidence::ProductVersion {
                        directory: directory.to_owned(),
                        product: product.product.clone(),
                        company: product.company.clone(),
                    };
                }
            }
            GroupingEvidence::ExecutablePath { path: path.clone() }
        });

        let index = match &grouping {
            Some(identity) => *by_identity.entry(identity.clone()).or_insert(groups.len()),
            None => groups.len(),
        };
        if index == groups.len() {
            groups.push((grouping, Vec::new()));
        }
        groups[index].1.push(process);
    }
    let mut apps: Vec<_> = groups
        .into_iter()
        .map(|(grouping, processes)| app_row(grouping, processes))
        .collect();
    apps.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.processes[0].pid.cmp(&right.processes[0].pid))
    });
    apps
}

fn outside_windows(directory: &Path, system_root: &Path) -> bool {
    let mut components = directory.components();
    if !matches!(components.clone().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_)))
    {
        return false;
    }
    !system_root.components().all(|part| {
        components
            .next()
            .is_some_and(|next| part.as_os_str().eq_ignore_ascii_case(next.as_os_str()))
    })
}

fn app_row(grouping: Option<GroupingEvidence>, mut processes: Vec<Process>) -> App {
    processes.sort_by_key(|process| (process.pid, process.creation_time_100ns));
    let name = match &grouping {
        Some(GroupingEvidence::ProductVersion { product, .. }) => product.clone(),
        _ => processes[0].name.clone(),
    };
    let mut any_native = false;
    let mut any_emulated = false;
    let mut any_unknown = false;
    for process in &processes {
        match process.classification.architecture {
            ProcessArchitecture::NativeArm64 => any_native = true,
            ProcessArchitecture::EmulatedX64 | ProcessArchitecture::EmulatedX86 => {
                any_emulated = true
            }
            ProcessArchitecture::CouldNotVerify => any_unknown = true,
        }
    }
    let architecture = match (any_native, any_emulated, any_unknown) {
        (true, true, _) => AppArchitecture::Mixed,
        (true, false, false) => AppArchitecture::NativeArm64,
        (false, true, false) => AppArchitecture::Emulated,
        _ => AppArchitecture::CouldNotVerify,
    };
    App {
        name,
        architecture,
        grouping,
        cpu_percent: processes.iter().map(|process| process.cpu_percent).sum(),
        working_set_bytes: processes
            .iter()
            .map(|process| process.working_set_bytes)
            .sum(),
        processes,
    }
}

fn explanation(message: impl Into<String>) -> Evidence {
    Evidence::Explanation {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
