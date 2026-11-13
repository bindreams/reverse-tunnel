//! The machine's `Path` on Windows, which `install` adds the bin dir to and `uninstall` removes it from, as rustup does
//! to the user's `Path`: edited in the registry, then every program is told to read the environment again.

use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use winreg::RegValue;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_EXPAND_SZ, REG_SZ};

const KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const NAME: &str = "Path";
/// The value, as an error names it.
const VALUE: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path";

/// How long a window that does not answer the notification is waited for, in milliseconds. The windows are other
/// programs', which may hang; the notification is a courtesy, and the edit is already made.
const BROADCAST_TIMEOUT: u32 = 5000;

/// Puts `dir` on the machine's `Path`, unless an entry names it already.
pub fn add(dir: &Path) -> Result<()> {
    edit(dir, with_entry)
}

/// Removes every entry that names `dir` from the machine's `Path`.
pub fn remove(dir: &Path) -> Result<()> {
    edit(dir, without_entry)
}

/// Replaces the `Path` by what `change` makes of it, if it makes anything, keeping the value's type, then tells the
/// programs that run to read their environment again.
fn edit(dir: &Path, change: fn(&str, &str) -> Option<String>) -> Result<()> {
    let dir = dir.to_str().context("the directory is not Unicode")?;
    let key = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
        .with_context(|| format!("opening HKLM\\{KEY}"))?;
    let (current, vtype) = match key.get_raw_value(NAME) {
        Ok(value) => (decode(&value.bytes)?, value.vtype),
        Err(err) if err.kind() == ErrorKind::NotFound => (String::new(), REG_EXPAND_SZ),
        Err(err) => return Err(err).with_context(|| format!("reading {VALUE}")),
    };
    if !matches!(vtype, REG_SZ | REG_EXPAND_SZ) {
        bail!("{VALUE} is not a string, so it was not changed");
    }
    let Some(changed) = change(&current, dir) else {
        return Ok(());
    };
    key.set_raw_value(
        NAME,
        &RegValue {
            bytes: encode(&changed).into(),
            vtype,
        },
    )
    .with_context(|| format!("writing {VALUE}"))?;
    broadcast();
    Ok(())
}

/// Tells every top-level window that the environment changed, so that a new shell started from Explorer sees it.
fn broadcast() {
    let area: Vec<u16> = "Environment".encode_utf16().chain([0]).collect();
    // SAFETY: `area` is NUL-terminated and outlives the call, which returns only when every window has handled the
    // message or has not answered within the timeout.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            area.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            BROADCAST_TIMEOUT,
            std::ptr::null_mut(),
        );
    }
}

/// Whether the `Path` entry `entry` names the directory `dir`: by whatever case, with or without quotes and a trailing
/// backslash.
fn names(entry: &str, dir: &str) -> bool {
    let bare = |text: &str| text.trim_matches('"').trim_end_matches('\\').to_lowercase();
    bare(entry) == bare(dir)
}

/// `path` with `dir` appended, or none if an entry names it already.
fn with_entry(path: &str, dir: &str) -> Option<String> {
    if path.split(';').any(|entry| names(entry, dir)) {
        None
    } else if path.is_empty() || path.ends_with(';') {
        Some(format!("{path}{dir}"))
    } else {
        Some(format!("{path};{dir}"))
    }
}

/// `path` without the entries that name `dir`, each with its separator; none if no entry does. Other entries, empty
/// ones too, are as they were.
fn without_entry(path: &str, dir: &str) -> Option<String> {
    let kept: Vec<&str> = path.split(';').filter(|entry| !names(entry, dir)).collect();
    let changed = kept.join(";");
    (changed != path).then_some(changed)
}

/// The text of a registry string: UTF-16 with its terminating NULs.
fn decode(bytes: &[u8]) -> Result<String> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(anyhow!("{VALUE} is not UTF-16"));
    }
    let units: Vec<u16> = units.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    let text = String::from_utf16(&units).with_context(|| format!("{VALUE} is not valid UTF-16"))?;
    Ok(text.trim_end_matches('\0').to_string())
}

/// A registry string's bytes: UTF-16 and one terminating NUL.
fn encode(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
#[path = "system_path_tests.rs"]
mod tests;
