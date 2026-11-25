use super::*;

const PE_START: usize = 0x80;
const OPTIONAL_START: usize = PE_START + SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER;
const RAW_START: usize = 0x200;
const RAW_SIZE: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;

// The fixtures contain a DOS header, a PE header, and one file-backed section.
fn image(machine: u16, is_64: bool) -> Vec<u8> {
    let mut bytes = vec![0; RAW_START + RAW_SIZE];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3C, PE_START as u32);
    bytes[PE_START..PE_START + 4].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, PE_START + 4, machine);
    put_u16(&mut bytes, PE_START + 6, 1);
    let fixed_size = if is_64 { 112 } else { 96 };
    let optional_size = fixed_size + 16 * 8;
    put_u16(&mut bytes, PE_START + 20, optional_size as u16);
    put_u16(&mut bytes, PE_START + 22, 0x0002);
    put_u16(
        &mut bytes,
        OPTIONAL_START,
        if is_64 { MAGIC_64 } else { MAGIC_32 },
    );
    put_u32(&mut bytes, OPTIONAL_START + 32, SECTION_RVA);
    put_u32(&mut bytes, OPTIONAL_START + 36, RAW_SIZE as u32);
    put_u32(&mut bytes, OPTIONAL_START + fixed_size - 4, 16);

    let section_start = OPTIONAL_START + optional_size;
    bytes[section_start..section_start + 6].copy_from_slice(b".rdata");
    put_u32(&mut bytes, section_start + 8, RAW_SIZE as u32);
    put_u32(&mut bytes, section_start + 12, SECTION_RVA);
    put_u32(&mut bytes, section_start + 16, RAW_SIZE as u32);
    put_u32(&mut bytes, section_start + 20, RAW_START as u32);
    bytes
}

fn add_load_config(bytes: &mut [u8]) {
    let config_entry = OPTIONAL_START + 112 + 10 * 8;
    put_u32(bytes, config_entry, SECTION_RVA);
    put_u32(bytes, config_entry + 4, 240);
    put_u32(bytes, RAW_START, 240);
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn classifies_arm64_x64_and_x86_from_their_pe_headers() {
    for (machine, is_64, architecture) in [
        (COFF_MACHINE_ARM64, true, FileArchitecture::Arm64),
        (COFF_MACHINE_X86_64, true, FileArchitecture::X64),
        (COFF_MACHINE_X86, false, FileArchitecture::X86),
    ] {
        let result =
            check_pe(&image(machine, is_64)).expect("fixture should have a readable image");
        assert_eq!(
            result,
            FileCheck {
                architecture,
                hybrid: false,
                evidence: vec![Evidence::PeHeader { machine }],
            }
        );
    }
}

#[test]
fn reports_explicit_hybrid_and_unknown_machine_codes() {
    for (machine, explanation) in [
        (MACHINE_ARM64EC, "ARM64EC machine code"),
        (MACHINE_ARM64X, "ARM64X machine code"),
        (0x9999, "Unrecognized PE machine code"),
    ] {
        let result = check_pe(&image(machine, true)).expect("fixture should have a readable image");
        assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
        assert_eq!(
            result.hybrid,
            matches!(machine, MACHINE_ARM64EC | MACHINE_ARM64X)
        );
        assert_eq!(
            result.evidence,
            vec![
                Evidence::PeHeader { machine },
                Evidence::Explanation {
                    message: explanation.to_owned()
                },
            ]
        );
    }
}

#[test]
fn finds_hybrid_metadata_under_arm64_and_x64_machine_codes() {
    for machine in [COFF_MACHINE_ARM64, COFF_MACHINE_X86_64] {
        let mut bytes = image(machine, true);
        add_load_config(&mut bytes);
        put_u32(&mut bytes, RAW_START + 200, 0x1234);

        let result = check_pe(&bytes).expect("fixture should have a readable image");
        assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
        assert_eq!(result.evidence[0], Evidence::PeHeader { machine });
        assert!(
            matches!(&result.evidence[1], Evidence::Explanation { message } if message.contains("hybrid metadata pointer"))
        );
    }
}

#[test]
fn finds_arm64x_relocation_without_a_hybrid_metadata_pointer() {
    let mut bytes = image(COFF_MACHINE_ARM64, true);
    add_load_config(&mut bytes);
    put_u32(&mut bytes, RAW_START + 224, 0x100);
    put_u16(&mut bytes, RAW_START + 228, 1);
    let table = RAW_START + 0x100;
    put_u32(&mut bytes, table, 1);
    put_u32(&mut bytes, table + 4, 12);
    put_u32(&mut bytes, table + 8, ARM64X_RELOCATION as u32);

    let result = check_pe(&bytes).expect("fixture should have a readable image");
    assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
    assert!(
        matches!(&result.evidence[1], Evidence::Explanation { message } if message.contains("ARM64X dynamic relocation"))
    );

    put_u32(&mut bytes, table + 8, 3);
    let result = check_pe(&bytes).expect("fixture should have a readable image");
    assert_eq!(result.architecture, FileArchitecture::Arm64);
}

#[test]
fn finds_arm64x_in_version_two_dynamic_relocations() {
    let mut bytes = image(COFF_MACHINE_ARM64, true);
    add_load_config(&mut bytes);
    put_u32(&mut bytes, RAW_START + 224, 0x100);
    put_u16(&mut bytes, RAW_START + 228, 1);
    let table = RAW_START + 0x100;
    put_u32(&mut bytes, table, 2);
    put_u32(&mut bytes, table + 4, 24);
    put_u32(&mut bytes, table + 8, 24);
    put_u32(&mut bytes, table + 16, ARM64X_RELOCATION as u32);

    let result = check_pe(&bytes).expect("fixture should have a readable image");
    assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
    assert!(
        matches!(&result.evidence[1], Evidence::Explanation { message } if message.contains("ARM64X dynamic relocation"))
    );
}

#[test]
fn preserves_machine_code_when_hybrid_metadata_cannot_be_read() {
    let mut bytes = image(COFF_MACHINE_ARM64, true);
    add_load_config(&mut bytes);
    put_u32(&mut bytes, RAW_START, 4096);

    let result = check_pe(&bytes).expect("fixture should have a readable image header");
    assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
    assert_eq!(
        result.evidence[0],
        Evidence::PeHeader {
            machine: COFF_MACHINE_ARM64
        }
    );
    assert!(
        matches!(&result.evidence[1], Evidence::Explanation { message } if message.contains("invalid load configuration size"))
    );
}

#[test]
fn rejects_non_pe_and_truncated_inputs() {
    assert!(matches!(
        check_pe(b"plain text"),
        Err(CheckFileError::NotPe)
    ));
    let mut bytes = image(COFF_MACHINE_ARM64, true);
    bytes[PE_START] = b'N';
    assert!(matches!(
        check_pe(&bytes),
        Err(CheckFileError::InvalidHeader(_))
    ));

    let bytes = image(COFF_MACHINE_ARM64, true);
    assert!(matches!(
        check_pe(&bytes[..PE_START + 5]),
        Err(CheckFileError::InvalidHeader(_))
    ));
    assert!(matches!(
        check_pe(&bytes[..RAW_START + 1]),
        Err(CheckFileError::InvalidImage(_))
    ));
}

#[test]
fn reports_inconsistent_machine_and_pe_bitness() {
    let result =
        check_pe(&image(COFF_MACHINE_X86, true)).expect("fixture should have a readable image");
    assert_eq!(result.architecture, FileArchitecture::CouldNotVerify);
    assert!(
        matches!(&result.evidence[1], Evidence::Explanation { message } if message.contains("bitness"))
    );
}

#[test]
fn reports_missing_files_and_directories() {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR"));
    let missing = folder.join("armcheck-fixture-not-on-disk.exe");
    assert!(
        matches!(check_file(&missing), Err(CheckFileError::Missing { path }) if path == missing)
    );
    assert!(matches!(check_file(folder), Err(CheckFileError::NotFile { path }) if path == folder));
}

#[test]
fn rejects_empty_input() {
    assert!(matches!(check_pe(&[]), Err(CheckFileError::NotPe)));
}
