use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::Path, ptr};

use ::windows::{
    Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
    core::{PCWSTR, w},
};

use super::ProductVersion;

pub(super) fn product_version(path: &Path) -> Option<ProductVersion> {
    let path_wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
    let path = PCWSTR(path_wide.as_ptr());
    let size = unsafe { GetFileVersionInfoSizeW(path, None) };
    if size == 0 || size > 1024 * 1024 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // The size query and the loading call use the same wide path and buffer size.
    unsafe { GetFileVersionInfoW(path, None, size, block.as_mut_ptr().cast()) }.ok()?;

    let translations = query(&block, w!("\\VarFileInfo\\Translation"), 1)?;
    let (translations, remainder) = translations.as_chunks::<4>();
    if !remainder.is_empty() {
        return None;
    }
    translations.iter().find_map(|entry| {
        let language = u16::from_le_bytes([entry[0], entry[1]]);
        let code_page = u16::from_le_bytes([entry[2], entry[3]]);
        let prefix = format!("\\StringFileInfo\\{language:04x}{code_page:04x}\\");
        Some(ProductVersion {
            product: version_string(&block, &format!("{prefix}ProductName"))?,
            company: version_string(&block, &format!("{prefix}CompanyName"))?,
        })
    })
}

fn version_string(block: &[u8], key: &str) -> Option<String> {
    let key: Vec<_> = key.encode_utf16().chain([0]).collect();
    let bytes = query(block, PCWSTR(key.as_ptr()), 2)?;
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .take_while(|unit| *unit != 0)
        .collect();
    let value = String::from_utf16(&units).ok()?;
    let trimmed = value.trim();
    (!trimmed.is_empty() && !trimmed.chars().any(char::is_control)).then(|| trimmed.to_owned())
}

fn query(block: &[u8], key: PCWSTR, bytes_per_unit: usize) -> Option<&[u8]> {
    let mut result: *mut c_void = ptr::null_mut();
    let mut units = 0;
    // VerQueryValueW returns a pointer into the supplied resource. Use a checked
    // slice of the original buffer instead of dereferencing that pointer.
    let success = unsafe { VerQueryValueW(block.as_ptr().cast(), key, &mut result, &mut units) };
    if !success.as_bool() {
        return None;
    }
    let offset = (result as usize).checked_sub(block.as_ptr() as usize)?;
    let byte_count = (units as usize).checked_mul(bytes_per_unit)?;
    block.get(offset..offset.checked_add(byte_count)?)
}
