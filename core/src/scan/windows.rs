use std::{
    ffi::OsString, mem::size_of, os::windows::ffi::OsStringExt, path::PathBuf, time::Instant,
};

use ::windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_NO_MORE_FILES, FILETIME, HANDLE, STILL_ACTIVE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            SystemInformation::{
                GetSystemTimePreciseAsFileTime, GetSystemWindowsDirectoryW, IMAGE_FILE_MACHINE,
            },
            Threading::{
                ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetExitCodeProcess,
                GetProcessInformation, GetProcessTimes, IsWow64Process2, OpenProcess,
                PROCESS_MACHINE_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                ProcessMachineTypeInfo, QueryFullProcessImageNameW,
            },
        },
    },
    core::{Error, PWSTR},
};

use super::{Observation, ProcessIdentity, ScanError, Timing, explanation};
use crate::model::Evidence;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // The constructor is only used for handles returned successfully by Win32.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn active_processor_count() -> u32 {
    unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }
}

pub(super) fn windows_directory() -> Option<PathBuf> {
    let mut buffer = [0u16; 260];
    let written = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
    (written > 0 && written < buffer.len())
        .then(|| PathBuf::from(OsString::from_wide(&buffer[..written])))
}

pub(super) fn snapshot(sample_memory: bool) -> Result<Vec<Observation>, ScanError> {
    // This UTC timestamp shares the FILETIME basis of process creation times.
    // Per-process elapsed intervals still use the monotonic Instant clock.
    let snapshot_started = filetime(unsafe { GetSystemTimePreciseAsFileTime() });
    let handle = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|source| ScanError {
            operation: "CreateToolhelp32Snapshot",
            source,
        })?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut processes = Vec::new();

    // The entry holds its own buffers, and dwSize identifies the structure to Win32.
    let mut result = unsafe { Process32FirstW(handle.0, &mut entry) };
    let mut operation = "Process32FirstW";
    loop {
        match result {
            Ok(()) => processes.push(observe(
                entry.th32ProcessID,
                wide_name(&entry.szExeFile),
                sample_memory,
                snapshot_started,
            )),
            Err(source) if win32_code(&source) == Some(ERROR_NO_MORE_FILES.0) => {
                return Ok(processes);
            }
            Err(source) => return Err(ScanError { operation, source }),
        }
        operation = "Process32NextW";
        result = unsafe { Process32NextW(handle.0, &mut entry) };
    }
}

fn wide_name(wide: &[u16]) -> String {
    let end = wide
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn observe(pid: u32, name: String, sample_memory: bool, snapshot_started: u64) -> Observation {
    let mut entry = Observation {
        pid,
        name,
        image_path: None,
        timing: None,
        working_set_bytes: None,
        evidence: Vec::new(),
    };

    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle(handle),
        Err(error) => {
            entry.evidence.push(error_evidence(
                "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)",
                error,
            ));
            return entry;
        }
    };
    let process = handle.0;
    entry.timing = timing(process, pid, snapshot_started, &mut entry.evidence);
    if sample_memory && entry.timing.is_some_and(|timing| timing.complete) {
        entry.working_set_bytes = working_set(process, &mut entry.evidence);
    }
    entry.image_path = image_path(process, &mut entry.evidence);
    if let Some(name) = entry
        .image_path
        .as_deref()
        .and_then(|path| path.file_name())
    {
        entry.name = name.to_string_lossy().into_owned();
    }
    record_runtime_type(process, &mut entry.evidence);
    entry
}

fn timing(
    handle: HANDLE,
    pid: u32,
    snapshot_started: u64,
    evidence: &mut Vec<Evidence>,
) -> Option<Timing> {
    let [mut created, mut exited, mut kernel, mut user] = [FILETIME::default(); 4];
    let result =
        unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) };
    let sampled_at = Instant::now();
    if let Err(error) = result {
        evidence.push(error_evidence("GetProcessTimes", error));
        return None;
    }
    let creation_time_100ns = filetime(created);
    let existed_at_snapshot = creation_time_100ns <= snapshot_started;
    if !existed_at_snapshot {
        evidence.push(explanation("Process started after this snapshot began"));
    }

    let mut exit_code = 0;
    let still_running = match unsafe { GetExitCodeProcess(handle, &mut exit_code) } {
        Ok(()) if exit_code == STILL_ACTIVE.0 as u32 => true,
        Ok(()) => {
            evidence.push(explanation(
                "Process exited before its sample could be collected",
            ));
            false
        }
        Err(error) => {
            evidence.push(error_evidence("GetExitCodeProcess", error));
            false
        }
    };
    Some(Timing {
        identity: ProcessIdentity {
            pid,
            creation_time_100ns,
        },
        cpu_ticks_100ns: filetime(kernel).checked_add(filetime(user))?,
        sampled_at,
        complete: existed_at_snapshot && still_running,
    })
}

fn filetime(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn working_set(handle: HANDLE, evidence: &mut Vec<Evidence>) -> Option<u64> {
    let size = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size,
        ..Default::default()
    };
    match unsafe { K32GetProcessMemoryInfo(handle, &mut counters, size) }.ok() {
        Ok(()) => Some(counters.WorkingSetSize as u64),
        Err(error) => {
            evidence.push(error_evidence("K32GetProcessMemoryInfo", error));
            None
        }
    }
}

fn image_path(handle: HANDLE, evidence: &mut Vec<Evidence>) -> Option<PathBuf> {
    const PATH_CAPACITY: usize = 32_768;
    let mut buffer = vec![0u16; PATH_CAPACITY];
    let mut length = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    match result {
        Ok(()) => Some(PathBuf::from(OsString::from_wide(
            &buffer[..length as usize],
        ))),
        Err(error) => {
            evidence.push(error_evidence("QueryFullProcessImageNameW", error));
            None
        }
    }
}

fn record_runtime_type(handle: HANDLE, evidence: &mut Vec<Evidence>) {
    let mut process_machine = IMAGE_FILE_MACHINE::default();
    let mut native_machine = IMAGE_FILE_MACHINE::default();
    let wow64 = unsafe { IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine)) };
    match wow64 {
        Ok(()) => evidence.push(Evidence::IsWow64Process2 {
            process_machine: process_machine.0,
            native_machine: native_machine.0,
        }),
        Err(error) => evidence.push(error_evidence("IsWow64Process2", error)),
    }

    let mut information = PROCESS_MACHINE_INFORMATION::default();
    let machine_type = unsafe {
        GetProcessInformation(
            handle,
            ProcessMachineTypeInfo,
            (&mut information as *mut PROCESS_MACHINE_INFORMATION).cast(),
            size_of::<PROCESS_MACHINE_INFORMATION>() as u32,
        )
    };
    match machine_type {
        Ok(()) => evidence.push(Evidence::ProcessMachineType {
            machine: information.ProcessMachine.0,
            machine_attributes: information.MachineAttributes.0 as u32,
        }),
        Err(error) => evidence.push(error_evidence(
            "GetProcessInformation(ProcessMachineTypeInfo)",
            error,
        )),
    }
}

fn win32_code(error: &Error) -> Option<u32> {
    // The windows crate wraps GetLastError in an HRESULT with FACILITY_WIN32.
    let code = error.code().0 as u32;
    (code & 0xFFFF_0000 == 0x8007_0000).then_some(code & 0xFFFF)
}

fn error_evidence(operation: &'static str, error: Error) -> Evidence {
    match win32_code(&error) {
        Some(code) => Evidence::Win32Error {
            operation: operation.to_owned(),
            code,
        },
        None => explanation(format!("{operation}: {error}")),
    }
}
