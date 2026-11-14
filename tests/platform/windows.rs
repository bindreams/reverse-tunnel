//! What the platform tests need of Windows: a DACL's effective rights, a job object that ends a session, a local
//! standard user, the machine's `Path` and the leftover images a removal renames.

use std::cell::Cell;
use std::fs;
use std::io::ErrorKind;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::ptr::{null, null_mut};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reverse_tunnel::account;
use reverse_tunnel::install;
use reverse_tunnel::security::{Sid, owner_of};
use reverse_tunnel::system_path;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, RegType};

use super::{Machine, output_of, service, service_owner, wait_until};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const EVERYONE: &str = "S-1-1-0";
const USERS: &str = "S-1-5-32-545";
const AUTHENTICATED_USERS: &str = "S-1-5-11";

/// File rights: everything; read and execute; and everything that changes the object or its ACL.
const FULL: u32 = 0x1f01ff;
const READ_EXECUTE: u32 = 0x1200a9;
const MODIFY: u32 = 0x1301bf;
const WRITE: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000;

/// The SID that `text` spells.
pub fn sid(text: &str) -> Sid {
    Sid::parse(text).unwrap_or_else(|err| panic!("{text} is not a SID: {err}"))
}

/// The rights `path`'s DACL gives the SID `trustee_sid`, as Windows works them out from every ACE that names it.
pub fn effective_rights(path: &Path, trustee_sid: &Sid) -> u32 {
    let wide = |text: &std::ffi::OsStr| -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        text.encode_wide().chain([0]).collect()
    };
    let (mut dacl, mut descriptor) = (null_mut(), null_mut());
    let mut rights = 0;
    // SAFETY: the strings are NUL-terminated, the out pointers are live, and what Windows allocated is freed below.
    unsafe {
        let path_text = wide(path.as_os_str());
        let found = GetNamedSecurityInfoW(
            path_text.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        );
        assert_eq!(found, 0, "reading the DACL of {}", path.display());
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: trustee_sid.as_psid().cast(),
        };
        assert_eq!(
            GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights),
            0,
            "the rights of {} on {}",
            trustee_sid
                .text()
                .unwrap_or_else(|err| format!("a SID that cannot be written ({err})")),
            path.display()
        );
        LocalFree(descriptor);
    }
    rights
}

/// The ACLs and owners the installation is specified to give; the service account's own access is shown by frpc
/// running, which needs both tokens, and by the supervisor's files in `logs/`.
pub fn assert_installed_as_specified(machine: &Machine) {
    let paths = &machine.paths;
    let service_sid = account::ensure(service::ACCOUNT).unwrap().sid();
    // The text names the SID in a failure; the rights are asked of its binary form.
    let rights = |path: &Path, text: &str| effective_rights(path, &sid(text));
    let is = |path: &Path, sid: &str, wanted: u32| {
        assert_eq!(
            rights(path, sid) & wanted,
            wanted,
            "{sid} on {} lacks {wanted:#x}",
            path.display()
        );
    };
    let may_not_write = |path: &Path, sid: &str| {
        assert_eq!(
            rights(path, sid) & WRITE,
            0,
            "{sid} may write {}: {:#x}",
            path.display(),
            rights(path, sid)
        );
    };
    let has_no_access = |path: &Path, sid: &str| {
        assert_eq!(rights(path, sid), 0, "{sid} has access to {}", path.display());
    };
    let tokens = [
        machine.secrets().join("bridge.token"),
        machine.secrets().join("host.token"),
    ];

    for public in [
        paths.config_dir.clone(),
        paths.config_dir.join("config.yaml"),
        paths.config_dir.join("bridge.pem"),
    ] {
        is(&public, SYSTEM, FULL);
        is(&public, ADMINISTRATORS, FULL);
        is(&public, EVERYONE, READ_EXECUTE);
        may_not_write(&public, EVERYONE);
    }
    is(&paths.log_dir, EVERYONE, READ_EXECUTE);
    may_not_write(&paths.log_dir, EVERYONE);
    is(&paths.log_dir, &service_sid, MODIFY);
    for secret in [&paths.secrets_dir, &tokens[0], &tokens[1]] {
        is(secret, SYSTEM, FULL);
        is(secret, ADMINISTRATORS, FULL);
        is(secret, &service_sid, READ_EXECUTE);
        may_not_write(secret, &service_sid);
        for sid in [EVERYONE, USERS, AUTHENTICATED_USERS] {
            has_no_access(secret, sid);
        }
    }
    for binary in [&paths.bin_dir, &service::exe(paths)] {
        is(binary, ADMINISTRATORS, FULL);
        is(binary, EVERYONE, READ_EXECUTE);
        for sid in [EVERYONE, USERS, AUTHENTICATED_USERS, &service_sid] {
            may_not_write(binary, sid);
        }
    }
    let frpc = reverse_tunnel::download::tools(paths).frpc;
    for owned in [
        &paths.config_dir,
        &paths.secrets_dir,
        &paths.log_dir,
        &paths.bin_dir,
        &service::exe(paths),
        &frpc,
    ] {
        assert_eq!(owner_of(owned).unwrap(), ADMINISTRATORS, "owner of {}", owned.display());
    }
    // frpc runs only after the supervisor read both tokens, which it does as the service account.
    assert!(machine.wait_for_frpc().iter().all(|frpc| frpc.owner == service_owner()));
}

/// A job object that kills every process in it when its handle closes, as an OpenSSH session's does.
pub struct Job {
    handle: HANDLE,
    open: Cell<bool>,
}

impl Job {
    pub fn kill_on_close() -> Job {
        // SAFETY: plain calls with live pointers; the information struct is zeroed except for the flag.
        unsafe {
            let handle = CreateJobObjectW(null(), null());
            assert!(
                !handle.is_null(),
                "CreateJobObjectW: {}",
                std::io::Error::last_os_error()
            );
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let set = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            assert_ne!(set, 0, "SetInformationJobObject: {}", std::io::Error::last_os_error());
            Job {
                handle,
                open: Cell::new(true),
            }
        }
    }

    /// Puts `child` in the job, with everything it will start.
    pub fn add(&self, child: &Child) {
        // SAFETY: both handles are live.
        let added = unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle() as HANDLE) };
        assert_ne!(
            added,
            0,
            "AssignProcessToJobObject: {}",
            std::io::Error::last_os_error()
        );
    }

    /// Ends the session: kills what is in the job.
    pub fn close(&self) {
        if self.open.replace(false) {
            // SAFETY: the handle is live and closed once.
            unsafe { CloseHandle(self.handle) };
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.close();
    }
}

/// A local standard user, removed when it drops.
pub struct Probe;

const PROBE: &str = "rtprobe";
const PROBE_PASSWORD: &str = "Rt-probe-1aXz!";

impl Probe {
    pub fn create() -> Probe {
        output_of("net", &["user", PROBE, PROBE_PASSWORD, "/add"]);
        Probe
    }

    /// Runs `program` with `args` as the user, through the system's own logon, and waits for it. Its output is
    /// captured by files that the caller creates.
    pub fn run(&self, program: &Path, args: &str) -> Output {
        let scratch = tempfile::tempdir_in(r"C:\Users\Public").unwrap();
        let (out, err) = (scratch.path().join("out.txt"), scratch.path().join("err.txt"));
        let quote = |text: &str| text.replace('\'', "''");
        let script = format!(
            "$password = ConvertTo-SecureString '{}' -AsPlainText -Force; \
             $credential = New-Object System.Management.Automation.PSCredential('.\\{PROBE}', $password); \
             $run = Start-Process -FilePath '{}' -ArgumentList '{}' -Credential $credential -WorkingDirectory 'C:\\Users\\Public' \
             -Wait -PassThru -RedirectStandardOutput '{}' -RedirectStandardError '{}'; exit $run.ExitCode",
            quote(PROBE_PASSWORD),
            quote(&program.display().to_string()),
            quote(args),
            quote(&out.display().to_string()),
            quote(&err.display().to_string()),
        );
        let encoded = STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());
        let launched = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
            .unwrap();
        assert!(
            launched.status.code().is_some(),
            "powershell: {}",
            String::from_utf8_lossy(&launched.stderr)
        );
        Output {
            status: launched.status,
            stdout: fs::read(&out).unwrap_or_default(),
            // What PowerShell could not start the program with is its own error.
            stderr: [fs::read(&err).unwrap_or_default(), launched.stderr].concat(),
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = Command::new("net").args(["user", PROBE, "/delete"]).output();
    }
}

/// The key under `HKEY_LOCAL_MACHINE` that holds the system's boot-time settings.
const SESSION_MANAGER: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";

/// The text of a registry string with its NULs, replacing what is not UTF-16: other programs' values are read, and an
/// odd one must not stop the test.
fn registry_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The key that holds the machine's `Path`.
fn environment() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"{SESSION_MANAGER}\Environment"))
        .unwrap()
}

/// The machine's `Path` as stored, unexpanded and without its terminating NULs, with its registry type. The product
/// writes this value, so text that is not UTF-16 fails the test.
pub fn machine_path_and_type() -> (String, RegType) {
    let value = environment().get_raw_value("Path").unwrap();
    let (units, rest) = value.bytes.as_chunks::<2>();
    assert!(rest.is_empty(), "the machine's Path is not UTF-16");
    let units: Vec<u16> = units.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    let text = String::from_utf16(&units).expect("the machine's Path is not valid UTF-16");
    (text.trim_end_matches('\0').to_string(), value.vtype)
}

/// The machine's `Path`, as stored: unexpanded.
fn machine_path() -> String {
    machine_path_and_type().0
}

/// `source` without the prefixes of a pending operation's source: `*1` for a long name, then `\??\`.
fn nt_path_of(source: &str) -> &str {
    let source = source
        .strip_prefix('*')
        .map_or(source, |rest| rest.trim_start_matches(|c: char| c.is_ascii_digit()));
    source.strip_prefix(r"\??\").unwrap_or(source)
}

/// What the system deletes at its next boot, in the order it deletes it. The value is a multi-string of source and
/// target pairs, each source `[*1]\??\<path>`, a target empty for a deletion; a pair that is not one is another program's
/// and is skipped.
pub fn deletions_at_reboot() -> Vec<PathBuf> {
    let session = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(SESSION_MANAGER).unwrap();
    let value = match session.get_raw_value("PendingFileRenameOperations") {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(err) => panic!("reading PendingFileRenameOperations: {err}"),
    };
    let text = registry_text(&value.bytes);
    // Walk the strings from the start in (source, target) pairs; an empty source ends the list, as it does for Windows,
    // whatever NULs or stale data follow.
    let mut strings = text.split('\0');
    let mut deletions = Vec::new();
    while let (Some(source), Some(target)) = (strings.next(), strings.next()) {
        if source.is_empty() {
            break;
        }
        if target.is_empty() {
            deletions.push(PathBuf::from(nt_path_of(source)));
        }
    }
    deletions
}

/// How many entries of the machine's `Path` name `dir`, as the product decides it.
pub fn path_entries_naming(dir: &Path) -> usize {
    let dir = dir.to_str().unwrap();
    machine_path()
        .split(';')
        .filter(|entry| system_path::names(entry, dir).unwrap())
        .count()
}

/// The machine's `Path` as a process started now would have it, each `%NAME%` expanded: the environment of a shell
/// opened after `install`, unlike this process's own.
pub fn fresh_path() -> String {
    system_path::expand(&machine_path()).unwrap()
}

/// Waits, with no cap, until the removal's task has deleted every file matching `schtasks::leftover_pattern`.
pub fn wait_until_no_leftover_image_is_left(machine: &Machine) {
    wait_until("the leftover images are deleted", || {
        install::leftover_images(&machine.paths).unwrap().is_empty()
    });
}
