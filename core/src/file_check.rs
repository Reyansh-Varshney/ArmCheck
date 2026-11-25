use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    mem::{offset_of, size_of},
    path::{Path, PathBuf},
};

use goblin::pe::{
    clr::{
        COMIMAGE_FLAGS_32BITPREFERRED, COMIMAGE_FLAGS_32BITREQUIRED, COMIMAGE_FLAGS_ILONLY,
        COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, Cor20Header, DOTNET_SIGNATURE,
    },
    data_directories::DataDirectory,
    header::{
        COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64, CoffHeader, DOS_STUB_OFFSET,
        Header, PE_POINTER_OFFSET, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC,
    },
    load_config::LoadConfigData,
    optional_header::{MAGIC_32, MAGIC_64, OptionalHeader},
    options::ParseOptions,
    section_table::{SIZEOF_SECTION_TABLE, SectionTable},
};
use thiserror::Error;

use crate::model::{Evidence, FileArchitecture, FileCheck};

const MACHINE_ARM64EC: u16 = 0xA641;
const MACHINE_ARM64X: u16 = 0xA64E;
const ARM64X_RELOCATION: u64 = 6;
const PE_READ_LIMIT: u64 = 1024 * 1024;

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
    #[error("PE inspection exceeds the {PE_READ_LIMIT}-byte read limit")]
    ReadLimit,
}

pub fn check_file(path: &Path) -> Result<FileCheck, CheckFileError> {
    let metadata = fs::metadata(path).map_err(|error| read_error(path, error))?;
    if !metadata.is_file() {
        return Err(CheckFileError::NotFile {
            path: path.to_path_buf(),
        });
    }

    let file = File::open(path).map_err(|error| read_error(path, error))?;
    let length = file
        .metadata()
        .map_err(|error| read_error(path, error))?
        .len();
    inspect_pe(&mut PeReader::new(file, length, path))
}

fn read_error(path: &Path, source: io::Error) -> CheckFileError {
    let path = path.to_path_buf();
    match source.kind() {
        io::ErrorKind::NotFound => CheckFileError::Missing { path },
        _ => CheckFileError::Read { path, source },
    }
}

struct PeReader<'a, R> {
    source: R,
    length: u64,
    remaining: u64,
    path: &'a Path,
}

impl<'a, R: Read + Seek> PeReader<'a, R> {
    fn new(source: R, length: u64, path: &'a Path) -> Self {
        Self {
            source,
            length,
            remaining: PE_READ_LIMIT,
            path,
        }
    }

    fn read_at(&mut self, offset: u64, size: u64) -> Result<Vec<u8>, CheckFileError> {
        if size > self.remaining {
            return Err(CheckFileError::ReadLimit);
        }
        if offset > self.length || size > self.length - offset {
            return Err(CheckFileError::InvalidImage(
                "requested PE data extends past the file",
            ));
        }

        self.remaining -= size;
        let mut bytes = vec![0; size as usize];
        self.source
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.source.read_exact(&mut bytes))
            .map_err(|error| read_error(self.path, error))?;
        Ok(bytes)
    }
}

#[cfg(test)]
fn check_pe(bytes: &[u8]) -> Result<FileCheck, CheckFileError> {
    inspect_pe(&mut PeReader::new(
        io::Cursor::new(bytes),
        bytes.len() as u64,
        Path::new("<memory>"),
    ))
}

fn inspect_pe(reader: &mut PeReader<'_, impl Read + Seek>) -> Result<FileCheck, CheckFileError> {
    let dos = reader.read_at(0, reader.length.min(u64::from(DOS_STUB_OFFSET)))?;
    if !dos.starts_with(b"MZ") {
        return Err(CheckFileError::NotPe);
    }
    let pe_offset = read_u32(&dos, PE_POINTER_OFFSET as usize)
        .map(u64::from)
        .ok_or_else(|| goblin::error::Error::Malformed("missing PE header pointer".into()))?;
    let coff_size = (SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER) as u64;
    if pe_offset + coff_size > reader.length {
        return Err(goblin::error::Error::Malformed("incomplete PE file header".into()).into());
    }
    let coff_bytes = reader.read_at(pe_offset, coff_size)?;
    let mut coff_offset = SIZEOF_PE_MAGIC;
    let coff = CoffHeader::parse(&coff_bytes, &mut coff_offset)?;
    let section_offset = pe_offset + coff_size + u64::from(coff.size_of_optional_header);
    let section_end =
        section_offset + u64::from(coff.number_of_sections) * SIZEOF_SECTION_TABLE as u64;
    // Goblin checks the DOS stub and PE headers together. Read that prefix only.
    let headers = reader.read_at(0, section_end.min(reader.length))?;
    let header = Header::parse(&headers)?;
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

    if section_end > reader.length {
        return Err(CheckFileError::InvalidImage("incomplete PE section table"));
    }
    let mut section_offset = section_offset as usize;
    let sections = coff.sections(&headers, &mut section_offset)?;
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
        let raw_end = u64::from(section.pointer_to_raw_data) + u64::from(section.size_of_raw_data);
        if section.size_of_raw_data != 0 && raw_end > reader.length {
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

    let (explanation, hybrid) = match explanation {
        Some(message) => (
            Some(message.to_owned()),
            matches!(machine, MACHINE_ARM64EC | MACHINE_ARM64X),
        ),
        None if is_64 => match hybrid_marker(reader, &optional, &sections) {
            Ok(marker) => (marker.map(str::to_owned), marker.is_some()),
            Err(error) => (
                Some(format!("Could not verify PE hybrid metadata: {error}")),
                false,
            ),
        },
        None => (None, false),
    };
    let mut architecture = match explanation {
        Some(message) => {
            evidence.push(Evidence::Explanation { message });
            FileArchitecture::CouldNotVerify
        }
        None => architecture,
    };
    if architecture == FileArchitecture::X86
        && let Some(&directory) = optional.data_directories.get_clr_runtime_header()
    {
        match managed_any_cpu(reader, directory, &sections) {
            Ok(Some(flags)) => {
                architecture = FileArchitecture::ManagedAnyCpu;
                evidence.push(Evidence::Explanation {
                    message: format!(
                        "CLR flags 0x{flags:08X} indicate architecture-neutral .NET IL (AnyCPU)"
                    ),
                });
            }
            Ok(None) => {}
            Err(error) => {
                architecture = FileArchitecture::CouldNotVerify;
                evidence.push(Evidence::Explanation {
                    message: format!("Could not verify CLR architecture: {error}"),
                });
            }
        }
    }
    Ok(FileCheck {
        architecture,
        hybrid,
        evidence,
    })
}

fn managed_any_cpu(
    reader: &mut PeReader<'_, impl Read + Seek>,
    directory: DataDirectory,
    sections: &[SectionTable],
) -> Result<Option<u32>, String> {
    const HEADER_SIZE: u64 = size_of::<Cor20Header>() as u64;
    let offset = section_file_offset(directory, sections)
        .filter(|_| u64::from(directory.size) >= HEADER_SIZE)
        .ok_or("CLR header is outside the file-backed sections or is too small")?;
    let header = reader
        .read_at(offset, HEADER_SIZE)
        .map_err(|error| error.to_string())?;
    let header_size =
        read_u32(&header, offset_of!(Cor20Header, cb)).ok_or("CLR header size is missing")?;
    if u64::from(header_size) != HEADER_SIZE {
        return Err("unexpected CLR header size".into());
    }

    let flags = read_u32(&header, offset_of!(Cor20Header, flags)).ok_or("CLR flags are missing")?;
    let mut metadata_entry = offset_of!(Cor20Header, metadata);
    let metadata =
        DataDirectory::parse(&header, &mut metadata_entry).map_err(|error| error.to_string())?;
    let metadata_offset = section_file_offset(metadata, sections)
        .filter(|_| metadata.size >= 4)
        .ok_or("CLR metadata is outside the file-backed sections or is too small")?;
    let signature = reader
        .read_at(metadata_offset, 4)
        .map_err(|error| error.to_string())?;
    if read_u32(&signature, 0) != Some(DOTNET_SIGNATURE) {
        return Err("CLR metadata signature is invalid".into());
    }

    if flags & COMIMAGE_FLAGS_ILONLY == 0 || flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0 {
        return Ok(None);
    }
    // A preference alone does not make an assembly x86-only, even when both
    // bitness flags are present for backward compatibility.
    if flags & COMIMAGE_FLAGS_32BITPREFERRED != 0 {
        return Err("CLR flags prefer 32-bit execution".into());
    }
    if flags & COMIMAGE_FLAGS_32BITREQUIRED != 0 {
        return Ok(None);
    }

    for mut directory_offset in [
        offset_of!(Cor20Header, managed_native_header),
        offset_of!(Cor20Header, vtable_fixups),
        offset_of!(Cor20Header, export_address_table_jumps),
    ] {
        let native_data = DataDirectory::parse(&header, &mut directory_offset)
            .map_err(|error| error.to_string())?;
        if native_data != DataDirectory::default() {
            return Err("CLR IL-only flags are accompanied by native metadata".into());
        }
    }

    Ok(Some(flags))
}

fn section_file_offset(directory: DataDirectory, sections: &[SectionTable]) -> Option<u64> {
    if directory.virtual_address == 0 || directory.size == 0 {
        return None;
    }
    sections.iter().find_map(|section| {
        let offset = directory
            .virtual_address
            .checked_sub(section.virtual_address)?;
        let end = offset.checked_add(directory.size)?;
        (end <= section.size_of_raw_data)
            .then(|| u64::from(section.pointer_to_raw_data) + u64::from(offset))
    })
}

fn hybrid_marker(
    reader: &mut PeReader<'_, impl Read + Seek>,
    optional: &OptionalHeader,
    sections: &[SectionTable],
) -> Result<Option<&'static str>, String> {
    let Some(&entry) = optional.data_directories.get_load_config_table() else {
        return Ok(None);
    };
    if entry.virtual_address == 0 || entry.size == 0 {
        return Err("invalid load configuration address or size".into());
    }
    let file_offset = section_file_offset(entry, sections)
        .ok_or("load configuration is outside the file-backed sections")?;
    let bytes = reader
        .read_at(file_offset, u64::from(entry.size))
        .map_err(|error| error.to_string())?;

    // The extracted directory starts at byte zero, so Goblin can parse it directly.
    let mut entry = entry;
    entry.virtual_address = 0;
    let mut options = ParseOptions::default();
    options.resolve_rva = false;
    let config = LoadConfigData::parse_with_opts(&bytes, entry, &[], 0, &options, true)
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
            let section = sections
                .get(usize::from(section_index))
                .ok_or("invalid dynamic relocation table section")?;
            let offset = u64::from(config.dynamic_value_reloc_table_offset.unwrap_or(0));
            let present = read_relocations(reader, section, offset)?;
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

fn read_relocations(
    reader: &mut PeReader<'_, impl Read + Seek>,
    section: &SectionTable,
    relative_offset: u64,
) -> Result<bool, String> {
    let available = u64::from(section.size_of_raw_data)
        .checked_sub(relative_offset)
        .filter(|size| *size >= 8)
        .ok_or("invalid dynamic relocation table offset")?;
    let offset = u64::from(section.pointer_to_raw_data) + relative_offset;
    let header = reader
        .read_at(offset, 8)
        .map_err(|error| error.to_string())?;
    let table_size =
        8 + u64::from(read_u32(&header, 4).ok_or("invalid dynamic relocation table size")?);
    if table_size > available {
        return Err("dynamic relocation table extends past its section".into());
    }
    let table = reader
        .read_at(offset, table_size)
        .map_err(|error| error.to_string())?;
    has_arm64x_relocation(&table).ok_or_else(|| "invalid dynamic relocation table".into())
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
