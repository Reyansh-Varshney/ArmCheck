use std::{
    fs, io,
    path::{Path, PathBuf},
};

use goblin::pe::{
    header::{
        COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64, Header, SIZEOF_COFF_HEADER,
        SIZEOF_PE_MAGIC,
    },
    load_config::LoadConfigData,
    optional_header::{MAGIC_32, MAGIC_64, OptionalHeader},
    section_table::SectionTable,
};
use thiserror::Error;

use crate::model::{Evidence, FileArchitecture, FileCheck};

const MACHINE_ARM64EC: u16 = 0xA641;
const MACHINE_ARM64X: u16 = 0xA64E;
const ARM64X_RELOCATION: u64 = 6;

#[derive(Debug, Error)]
pub enum CheckFileError {
    #[error("file not found: {}", .path.display())]
    Missing { path: PathBuf },
    #[error("expected a regular file: {}", .path.display())]
    NotFile { path: PathBuf },
    #[error("could not read {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("this is not a Windows PE file")]
    NotPe,
    #[error("invalid or truncated PE header: {0}")]
    InvalidHeader(#[from] goblin::error::Error),
    #[error("invalid or truncated PE image: {0}")]
    InvalidImage(&'static str),
}

pub fn check_file(path: &Path) -> Result<FileCheck, CheckFileError> {
    let metadata = fs::metadata(path).map_err(|error| read_error(path, error))?;
    if !metadata.is_file() {
        return Err(CheckFileError::NotFile {
            path: path.to_path_buf(),
        });
    }

    let bytes = fs::read(path).map_err(|error| read_error(path, error))?;
    check_pe(&bytes)
}

fn read_error(path: &Path, source: io::Error) -> CheckFileError {
    let path = path.to_path_buf();
    match source.kind() {
        io::ErrorKind::NotFound => CheckFileError::Missing { path },
        _ => CheckFileError::Read { path, source },
    }
}

fn check_pe(bytes: &[u8]) -> Result<FileCheck, CheckFileError> {
    if !bytes.starts_with(b"MZ") {
        return Err(CheckFileError::NotPe);
    }
    let header = Header::parse(bytes)?;
    let coff = header.coff_header;
    let machine = coff.machine;
    let optional = header
        .optional_header
        .ok_or(CheckFileError::InvalidImage("missing PE optional header"))?;
    let magic = optional.standard_fields.magic;
    let is_64 = magic == MAGIC_64;
    // PE32 and PE32+ have different fixed sizes before their data directories.
    let fixed_size = if is_64 { 112 } else { 96 };
    let directory_count = u64::from(optional.windows_fields.number_of_rva_and_sizes);
    if fixed_size + directory_count * 8 > u64::from(coff.size_of_optional_header) {
        return Err(CheckFileError::InvalidImage(
            "incomplete PE optional header",
        ));
    }

    let mut section_offset = header.dos_header.pe_pointer as usize
        + SIZEOF_PE_MAGIC
        + SIZEOF_COFF_HEADER
        + usize::from(coff.size_of_optional_header);
    if section_offset > bytes.len() {
        return Err(CheckFileError::InvalidImage("missing PE section table"));
    }
    let sections = coff.sections(bytes, &mut section_offset)?;
    for section in &sections {
        if section
            .virtual_address
            .checked_add(section.virtual_size)
            .is_none()
        {
            return Err(CheckFileError::InvalidImage(
                "invalid PE section address range",
            ));
        }
        if section.size_of_raw_data != 0 && section_data(bytes, section).is_none() {
            return Err(CheckFileError::InvalidImage("incomplete PE section data"));
        }
    }

    let mut evidence = vec![Evidence::PeHeader { machine }];
    let (architecture, explanation) = match (machine, magic) {
        (COFF_MACHINE_ARM64, MAGIC_64) => (FileArchitecture::Arm64, None),
        (COFF_MACHINE_X86_64, MAGIC_64) => (FileArchitecture::X64, None),
        (COFF_MACHINE_X86, MAGIC_32) => (FileArchitecture::X86, None),
        // TODO: Interpret ARM64EC and ARM64X images in a later version.
        (MACHINE_ARM64EC, _) => (
            FileArchitecture::CouldNotVerify,
            Some("ARM64EC machine code"),
        ),
        (MACHINE_ARM64X, _) => (
            FileArchitecture::CouldNotVerify,
            Some("ARM64X machine code"),
        ),
        (COFF_MACHINE_ARM64 | COFF_MACHINE_X86_64 | COFF_MACHINE_X86, _) => (
            FileArchitecture::CouldNotVerify,
            Some("The machine code and optional header disagree about the file's bitness"),
        ),
        _ => (
            FileArchitecture::CouldNotVerify,
            Some("Unrecognized PE machine code"),
        ),
    };

    let explanation = match explanation {
        Some(message) => Some(message.to_owned()),
        None if is_64 => match hybrid_marker(bytes, &optional, &sections) {
            Ok(marker) => marker.map(str::to_owned),
            Err(error) => Some(format!("Could not verify PE hybrid metadata: {error}")),
        },
        None => None,
    };
    let architecture = match explanation {
        Some(message) => {
            evidence.push(Evidence::Explanation { message });
            FileArchitecture::CouldNotVerify
        }
        None => architecture,
    };
    Ok(FileCheck {
        architecture,
        evidence,
    })
}

fn hybrid_marker(
    bytes: &[u8],
    optional: &OptionalHeader,
    sections: &[SectionTable],
) -> Result<Option<&'static str>, String> {
    let Some(&entry) = optional.data_directories.get_load_config_table() else {
        return Ok(None);
    };
    if entry.virtual_address == 0
        || entry.size == 0
        || !sections.iter().any(|section| {
            entry
                .virtual_address
                .checked_sub(section.virtual_address)
                .and_then(|offset| offset.checked_add(entry.size))
                .is_some_and(|end| end <= section.size_of_raw_data)
        })
    {
        return Err("load configuration is outside the file-backed sections".into());
    }
    let config = LoadConfigData::parse(
        bytes,
        entry,
        sections,
        optional.windows_fields.file_alignment,
        true,
    )
    .map_err(|error| error.to_string())?
    .directory;
    if !(4..=entry.size).contains(&config.size) {
        return Err("invalid load configuration size".into());
    }
    // The PE32+ load configuration grows over time. Check that each field
    // belongs to the version declared by this file before using its value.
    const CHPE_POINTER_END: u32 = 208;
    const RELOCATION_SECTION_END: u32 = 230;
    if config.size >= CHPE_POINTER_END && config.chpe_metadata_pointer.unwrap_or(0) != 0 {
        return Ok(Some(
            "PE load configuration contains an ARM64EC/ARM64X hybrid metadata pointer",
        ));
    }

    if config.size >= RELOCATION_SECTION_END {
        let section = config.dynamic_value_reloc_table_section.unwrap_or(0);
        if let Some(section_index) = section.checked_sub(1) {
            let offset = config.dynamic_value_reloc_table_offset.unwrap_or(0) as usize;
            let present = sections
                .get(usize::from(section_index))
                .and_then(|section| section_data(bytes, section))
                .and_then(|data| data.get(offset..))
                .and_then(has_arm64x_relocation)
                .ok_or("invalid dynamic relocation table")?;
            return Ok(
                present.then_some("PE load configuration points to an ARM64X dynamic relocation")
            );
        }
    }
    if config.size >= CHPE_POINTER_END && config.dynamic_value_reloc_table.unwrap_or(0) != 0 {
        return Err("dynamic relocation table has no section reference".into());
    }
    Ok(None)
}

fn section_data<'a>(bytes: &'a [u8], section: &SectionTable) -> Option<&'a [u8]> {
    let start = section.pointer_to_raw_data as usize;
    let end = start.checked_add(section.size_of_raw_data as usize)?;
    bytes.get(start..end)
}

fn has_arm64x_relocation(table: &[u8]) -> Option<bool> {
    let version = read_u32(table, 0)?;
    let size = read_u32(table, 4)? as usize;
    let mut entries = table.get(8..)?.get(..size)?;

    while !entries.is_empty() {
        let (header_size, payload_size, symbol_offset) = match version {
            1 => (12, read_u32(entries, 8)? as usize, 0),
            2 => {
                let header_size = read_u32(entries, 0)? as usize;
                if header_size < 24 {
                    return None;
                }
                (header_size, read_u32(entries, 4)? as usize, 8)
            }
            _ => return None,
        };
        let symbol = u64::from_le_bytes(
            entries
                .get(symbol_offset..symbol_offset + 8)?
                .try_into()
                .ok()?,
        );
        entries = entries.get(header_size.checked_add(payload_size)?..)?;
        if symbol == ARM64X_RELOCATION {
            return Some(true);
        }
    }
    matches!(version, 1 | 2).then_some(false)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests;
