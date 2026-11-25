use std::{mem::size_of, os::windows::ffi::OsStrExt, path::Path, ptr, slice};

use base64::{Engine, engine::general_purpose::STANDARD};
use windows::{
    Win32::{
        Graphics::Gdi::{
            BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection,
            DIB_RGB_COLORS, DeleteDC, DeleteObject, GdiFlush, HBITMAP, HDC, SelectObject,
        },
        UI::{
            Shell::ExtractIconExW,
            WindowsAndMessaging::{DI_NORMAL, DestroyIcon, DrawIconEx, HICON},
        },
    },
    core::PCWSTR,
};

const SIZE: i32 = 32;
const BYTES: usize = (SIZE * SIZE * 4) as usize;

struct Icon(HICON);
impl Drop for Icon {
    fn drop(&mut self) {
        let _ = unsafe { DestroyIcon(self.0) };
    }
}

struct MemoryDc(HDC);
impl Drop for MemoryDc {
    fn drop(&mut self) {
        let _ = unsafe { DeleteDC(self.0) };
    }
}

struct Bitmap(HBITMAP);
impl Drop for Bitmap {
    fn drop(&mut self) {
        let _ = unsafe { DeleteObject(self.0.into()) };
    }
}

pub fn executable_icon(path: &Path) -> Option<String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut handle = HICON::default();
    let count = unsafe { ExtractIconExW(PCWSTR(wide.as_ptr()), 0, Some(&mut handle), None, 1) };
    if count != 1 || handle.is_invalid() {
        return None;
    }
    let icon = Icon(handle);
    let rgba = render(&icon)?;
    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, SIZE as u32, SIZE as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.write_header().ok()?.write_image_data(&rgba).ok()?;
    }
    Some(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(png_bytes)
    ))
}

fn render(icon: &Icon) -> Option<Vec<u8>> {
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: SIZE,
            biHeight: -SIZE,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let dc = MemoryDc(unsafe { CreateCompatibleDC(None) });
    if dc.0.is_invalid() {
        return None;
    }
    let mut bits = ptr::null_mut();
    let bitmap = Bitmap(
        unsafe { CreateDIBSection(Some(dc.0), &info, DIB_RGB_COLORS, &mut bits, None, 0) }.ok()?,
    );
    if bits.is_null() {
        return None;
    }
    let previous = unsafe { SelectObject(dc.0, bitmap.0.into()) };
    if previous.is_invalid() {
        return None;
    }

    // Draw on black and white to recover opacity for both alpha and legacy mask icons.
    let draw = |background| -> Option<Vec<u8>> {
        // The selected 32-bit, 32-by-32 DIB owns this buffer for the lifetime of bitmap.
        unsafe { slice::from_raw_parts_mut(bits.cast::<u8>(), BYTES) }.fill(background);
        unsafe { DrawIconEx(dc.0, 0, 0, icon.0, SIZE, SIZE, 0, None, DI_NORMAL) }.ok()?;
        unsafe { GdiFlush() }.ok().ok()?;
        Some(unsafe { slice::from_raw_parts(bits.cast::<u8>(), BYTES) }.to_vec())
    };
    let dark = draw(0);
    let light = draw(255);
    unsafe { SelectObject(dc.0, previous) };
    let mut dark = dark?;
    let light = light?;
    for (on_black, on_white) in dark
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(light.as_chunks::<4>().0)
    {
        let alpha = 255 - on_white[0].saturating_sub(on_black[0]);
        if alpha != 0 {
            for channel in &mut on_black[..3] {
                *channel = (u16::from(*channel) * 255 / u16::from(alpha)).min(255) as u8;
            }
        }
        on_black.swap(0, 2);
        on_black[3] = alpha;
    }
    Some(dark)
}
