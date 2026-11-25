use std::{collections::HashSet, mem::size_of};

use windows::{
    Win32::{
        Foundation::{HWND, LPARAM},
        Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute},
        UI::WindowsAndMessaging::{
            EnumChildWindows, EnumWindows, GWL_EXSTYLE, GetClassNameW, GetWindowLongPtrW,
            GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible, WS_EX_TOOLWINDOW,
        },
    },
    core::{BOOL, Result},
};

pub fn process_ids() -> Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    // EnumWindows invokes this callback synchronously. The set lives until it returns.
    unsafe {
        EnumWindows(
            Some(collect_window),
            LPARAM(&mut pids as *mut HashSet<u32> as isize),
        )?
    };
    Ok(pids)
}

unsafe extern "system" fn collect_window(window: HWND, context: LPARAM) -> BOOL {
    if let Some(pid) = window_process(window) {
        // The callback receives the unique reference created in process_ids.
        unsafe { &mut *(context.0 as *mut HashSet<u32>) }.insert(pid);
    }
    BOOL(1)
}

fn window_process(window: HWND) -> Option<u32> {
    // IsWindowVisible tests the window style, which also covers minimized windows.
    // The title length omits blank utility windows without collecting any title text.
    if !unsafe { IsWindowVisible(window) }.as_bool()
        || unsafe { GetWindowTextLengthW(window) } <= 0
        || unsafe { GetWindowLongPtrW(window, GWL_EXSTYLE) } & WS_EX_TOOLWINDOW.0 as isize != 0
    {
        return None;
    }

    let mut cloaked = 0u32;
    unsafe {
        DwmGetWindowAttribute(
            window,
            DWMWA_CLOAKED,
            (&mut cloaked as *mut u32).cast(),
            size_of::<u32>() as u32,
        )
    }
    .ok()?;
    if cloaked != 0 {
        return None;
    }

    let pid = owner_pid(window)?;
    if !class_is(window, "ApplicationFrameWindow") {
        return Some(pid);
    }

    // A packaged app can put its content in a different process from the frame.
    // Attribute the window to that process only when one CoreWindow owner is observed.
    let mut children = HashSet::<u32>::new();
    unsafe {
        let _ = EnumChildWindows(
            Some(window),
            Some(collect_core_window),
            LPARAM(&mut children as *mut HashSet<u32> as isize),
        );
    }
    children.remove(&pid);
    if children.len() == 1 {
        children.into_iter().next()
    } else {
        None
    }
}

unsafe extern "system" fn collect_core_window(window: HWND, context: LPARAM) -> BOOL {
    if class_is(window, "Windows.UI.Core.CoreWindow")
        && let Some(pid) = owner_pid(window)
    {
        unsafe { &mut *(context.0 as *mut HashSet<u32>) }.insert(pid);
    }
    BOOL(1)
}

fn class_is(window: HWND, name: &str) -> bool {
    let mut class = [0u16; 64];
    let length = unsafe { GetClassNameW(window, &mut class) } as usize;
    class
        .get(..length)
        .is_some_and(|class| class.iter().copied().eq(name.encode_utf16()))
}

fn owner_pid(window: HWND) -> Option<u32> {
    let mut pid = 0;
    let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    (thread != 0 && pid != 0).then_some(pid)
}
