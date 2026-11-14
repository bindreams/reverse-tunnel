//! The machine's `Path` on Windows, which `install` adds the bin dir to and `uninstall` removes it from, as rustup does
//! to the user's `Path`: edited in the registry, then every program is told to read the environment again.
//!
//! The edit is a read, a change and a write: a concurrent edit by another program can lose one of the two.

use std::io::{self, ErrorKind};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
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
fn edit(dir: &Path, change: fn(&str, &str) -> Result<Option<String>>) -> Result<()> {
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
    let Some(changed) = change(&current, dir)? else {
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

/// Tells every top-level window of this session's desktop that the environment changed, so that a new shell started
/// from Explorer sees it. A process that is not on the desktop (a service, or an SSH session) cannot reach it.
pub fn broadcast() {
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

/// `text` with its `%NAME%` environment variables expanded, as a process that reads the `Path` would; one that is not
/// set stays as it is. Fails with the OS error if the expansion cannot be made.
pub fn expand(text: &str) -> Result<String> {
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated; the buffer has the length that is passed, and it is read up to what is written.
    unsafe {
        let needed = ExpandEnvironmentStringsW(wide.as_ptr(), std::ptr::null_mut(), 0);
        if needed == 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("expanding the variables in {text}"));
        }
        let mut expanded = vec![0u16; needed as usize];
        let written = ExpandEnvironmentStringsW(wide.as_ptr(), expanded.as_mut_ptr(), needed);
        if written == 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("expanding the variables in {text}"));
        }
        if written > needed {
            bail!("expanding the variables in {text}: the result grew while it was made");
        }
        Ok(String::from_utf16_lossy(&expanded[..written as usize - 1]))
    }
}

/// Whether the `Path` entry `entry` names the directory `dir`: once its variables are expanded, by whatever case, with
/// or without surrounding whitespace and quotes and a trailing backslash.
pub fn names(entry: &str, dir: &str) -> Result<bool> {
    let bare = |text: &str| -> Result<String> {
        let expanded = expand(text)?;
        let trimmed = expanded.trim_matches(|c: char| c.is_whitespace() || c == '"');
        Ok(trimmed.trim_end_matches('\\').to_lowercase())
    };
    Ok(bare(entry)? == bare(dir)?)
}

/// `path` with `dir` appended, or none if an entry names it already.
fn with_entry(path: &str, dir: &str) -> Result<Option<String>> {
    for entry in path.split(';') {
        if names(entry, dir)? {
            return Ok(None);
        }
    }
    Ok(Some(if path.is_empty() || path.ends_with(';') {
        format!("{path}{dir}")
    } else {
        format!("{path};{dir}")
    }))
}

/// `path` without the entries that name `dir`, each with its separator; none if no entry does. Other entries, empty
/// ones too, are as they were.
fn without_entry(path: &str, dir: &str) -> Result<Option<String>> {
    let mut kept = Vec::new();
    for entry in path.split(';') {
        if !names(entry, dir)? {
            kept.push(entry);
        }
    }
    let changed = kept.join(";");
    Ok((changed != path).then_some(changed))
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
