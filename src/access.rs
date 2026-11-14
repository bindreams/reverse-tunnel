//! Windows: whether the service account has what `run` opens, judged from each path's DACL alone.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

use crate::account;
use crate::download;
use crate::paths::Paths;
use crate::security::{self, Ace, Sid};
use crate::service;

/// The groups, as (SID, name), that the token of the service always holds, enabled: the service is credited with what
/// an ACE gives them. Measured on CI from the running service's token (`tests/platform.rs`, the test of this list), not
/// from what an access check would do. Left out: `Users` (a nested membership that machine configuration can change),
/// `This Organization` (which depends on the logon), the logon session's SID, CONSOLE LOGON, and the High mandatory
/// label, which is no group an ACE names.
pub const CREDITED: [(&str, &str); 5] = [
    ("S-1-1-0", "Everyone"),
    ("S-1-5-6", "SERVICE"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-2-0", "LOCAL"),
    ("S-1-5-80-0", "ALL SERVICES"),
];

/// A right that `run` needs, and the word for it in a failure.
pub type Right = (u32, &'static str);
const READ: Right = (FILE_GENERIC_READ, "read");
const RUN: Right = (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, "read and run");
/// In the log directory `run` creates its logs and `frpc.toml`, appends to them, and rotates a log by renaming it over
/// the old one, which deletes that.
const LOG: Right = (FILE_GENERIC_WRITE | DELETE, "create, write and delete files in");

/// Every path `run` opens, with what it needs of each; `exe` is the service binary, or at `install` its staged copy,
/// which is in the same folder with the same descriptor, since the binary is placed only after the check. It reads no directory's listing, and Windows lets a service
/// through a directory it has no right to (SeChangeNotifyPrivilege), so a directory is here only where `run` writes.
pub fn opens(paths: &Paths, exe: &Path) -> Vec<(PathBuf, Right)> {
    vec![
        (exe.to_path_buf(), RUN),
        (download::tools(paths).frpc, RUN),
        (paths.config_file(), READ),
        (paths.bridge_pem(), READ),
        (paths.bridge_token(), READ),
        (paths.host_token(), READ),
        (paths.log_dir.clone(), LOG),
    ]
}

/// Fails, naming each path and what is wrong, unless the service account has what `run` opens by the DACLs: an allow
/// for the account or for a credited group, and no deny ACE of any kind. `run --check` as the caller cannot show this:
/// an administrator reads what the account cannot.
pub fn check(paths: &Paths, exe: &Path) -> Result<()> {
    let account = Sid::parse(&account::ensure(service::ACCOUNT)?.sid()).context("the service account's SID")?;
    let mut who = vec![(account, service::ACCOUNT)];
    for (sid, name) in CREDITED {
        who.push((Sid::parse(sid).with_context(|| format!("the SID of {name}"))?, name));
    }
    let problems: Vec<String> = opens(paths, exe)
        .into_iter()
        .filter_map(|(path, right)| problem(&path, right, &who).map(|problem| format!("{}: {problem}", path.display())))
        .collect();
    ensure!(
        problems.is_empty(),
        "{}",
        problems.join(
            "
"
        )
    );
    Ok(())
}

/// Why the service account cannot have `right` of `path`, in the user's words.
fn problem(path: &Path, (needs, verb): Right, who: &[(Sid, &str)]) -> Option<String> {
    let account = service::ACCOUNT;
    let aces = match security::aces_of(path) {
        Ok(aces) => aces,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Some(format!("it is missing, and {account} needs to {verb} it"));
        }
        Err(err) => {
            return Some(format!(
                "its ACL cannot be read to see whether {account} may {verb} it: {err}"
            ));
        }
    };
    Some(match barrier_of(&aces, who, needs)? {
        Barrier::Denied(sid) => {
            format!("an ACE in its ACL denies access to {sid}. {account} must not be denied anything: remove that ACE.")
        }
        Barrier::NotAllowed => {
            let groups: Vec<&str> = who.iter().skip(1).map(|(_, name)| *name).collect();
            format!(
                "{account} cannot {verb} it: no ACE in its ACL allows that to {account} or to a group it always                  belongs to ({}). Allow {account} to {verb} it.",
                groups.join(", ")
            )
        }
    })
}

/// What stands between the service and the rights it needs.
#[derive(Debug)]
pub enum Barrier {
    /// An ACE denies this SID something. Any deny ACE is a barrier, whoever it names and whatever it denies.
    Denied(String),
    /// The allow ACEs for the service and its groups do not add up to the rights.
    NotAllowed,
}

/// What stands in the way of `who` (each SID with its name) having all of `needs`, as the DACL `aces` gives it: there
/// is no deny ACE at all (inherit-only ones too, which the object's contents get), and the allows for `who` add up to
/// `needs`. Allows for the object's contents only count for nothing. A sufficient condition, not AccessCheck: it
/// refuses a DACL whose order would let the account through, and ignores the owner and privileges.
fn barrier_of(aces: &[Ace], who: &[(Sid, &str)], needs: u32) -> Option<Barrier> {
    let mut allowed = 0;
    for ace in aces {
        if !ace.allows {
            return Some(Barrier::Denied(
                ace.sid
                    .text()
                    .unwrap_or_else(|err| format!("an SID that cannot be read ({err})")),
            ));
        }
        if !ace.inherit_only && who.iter().any(|(sid, _)| *sid == ace.sid) {
            allowed |= file_rights(ace.mask);
        }
    }
    (allowed & needs != needs).then_some(Barrier::NotAllowed)
}

/// The rights of a file that `mask` gives, the generic ones mapped as the file system maps them.
fn file_rights(mask: u32) -> u32 {
    let generic = [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (GENERIC_ALL, FILE_ALL_ACCESS),
    ];
    generic
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .fold(mask, |rights, (_, mapped)| rights | mapped)
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
