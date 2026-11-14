//! Windows: whether the service account has what `run` opens, judged from each path's DACL alone.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES,
};

use crate::account;
use crate::logfile::ROTATED;
use crate::paths::{FRPC_CONFIG, LOG_FRPC, LOG_SUPERVISOR, Paths};
use crate::security::{self, Ace, Dacl, Sid};
use crate::service;

/// The groups, as (SID, name), that the token of the service always holds, enabled: the service is credited with what
/// an ACE gives them. Measured on CI from the running service's token (`tests/platform.rs`, the test of this list), not
/// from what an access check would do. Left out: `Users` (a nested membership that machine configuration can change)
/// and the groups that depend on the logon or the session, not on the service.
pub const CREDITED: [(&str, &str); 5] = [
    ("S-1-1-0", "Everyone"),
    ("S-1-5-6", "SERVICE"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-2-0", "LOCAL"),
    ("S-1-5-80-0", "ALL SERVICES"),
];

/// CREATOR OWNER: in an ACE that files inherit, whoever makes the file. The service owns what it makes, which the
/// platform test of `CREDITED` asserts.
const CREATOR_OWNER: &str = "S-1-3-0";
static CREATOR_OWNER_SID: LazyLock<Sid> =
    LazyLock::new(|| Sid::parse(CREATOR_OWNER).expect("CREATOR_OWNER is a valid SID"));

/// A right that `run` needs, and the word for it in a failure.
pub type Right = (u32, &'static str);
const READ: Right = (FILE_GENERIC_READ, "read");
const RUN: Right = (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, "read and run");
/// Of the log directory itself: `run` makes files there, and renames a log there (rotation).
const MAKE_FILES: Right = (FILE_ADD_FILE, "create files in");
/// Of a file `run` makes in the log directory, which it gets by inheritance: `run` writes each, `frpc` reads
/// `frpc.toml`, and rotation renames a log over `<log>.1`, which needs DELETE on the log and on `<log>.1`.
const NEW_FILE: Right = (
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
    "read, write and delete",
);
/// Of a log: `run` appends to it, reads its size from the open file (`LogFile::open`: FILE_READ_ATTRIBUTES, which
/// FILE_GENERIC_WRITE lacks) and renames it over `<log>.1`.
const LOG: Right = (
    FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
    "write to, read the size of and delete",
);
const ROTATED_LOG: Right = (DELETE, "delete");
const RENDERED: Right = (FILE_GENERIC_READ | FILE_GENERIC_WRITE, "read and write");

/// The SIDs that count in a check.
pub struct Principals {
    /// `holders[0]` is the service account; the rest are the credited groups.
    pub holders: Vec<(Sid, &'static str)>,
}

/// A path `run` opens and what it needs of it.
pub struct Need {
    pub path: PathBuf,
    /// What the service needs of the path itself.
    pub itself: Right,
    /// For a directory where `run` makes files: what those must get by inheritance.
    pub files: Option<Right>,
    /// `run` makes it if it is missing, so a missing one is no failure.
    pub made_by_run: bool,
}

impl Need {
    fn of(path: PathBuf, itself: Right) -> Need {
        Need {
            path,
            itself,
            files: None,
            made_by_run: false,
        }
    }

    fn made(path: PathBuf, itself: Right) -> Need {
        Need {
            made_by_run: true,
            ..Need::of(path, itself)
        }
    }
}

/// Every path `run` opens, with what it needs of each. `exe` is the binary the service will run and `frpc` the one it
/// starts; at an `install`, `exe` is the staged copy, which gets the access the installed binary gets. A directory is
/// listed only where `run` makes files (the log dir); `run` lists none, and SeChangeNotifyPrivilege lets a service
/// through directories it has no right to (asserted by the platform test of `CREDITED`).
pub fn opens(paths: &Paths, exe: &Path, frpc: &Path) -> Vec<Need> {
    let logs = &paths.log_dir;
    let mut needs = vec![
        Need::of(exe.to_path_buf(), RUN),
        Need::of(frpc.to_path_buf(), RUN),
        Need::of(paths.config_file(), READ),
        Need::of(paths.bridge_pem(), READ),
        Need::of(paths.bridge_token(), READ),
        Need::of(paths.host_token(), READ),
        Need {
            files: Some(NEW_FILE),
            ..Need::of(logs.clone(), MAKE_FILES)
        },
        Need::made(logs.join(FRPC_CONFIG), RENDERED),
    ];
    for log in [LOG_SUPERVISOR, LOG_FRPC] {
        needs.push(Need::made(logs.join(log), LOG));
        needs.push(Need::made(logs.join(format!("{log}{ROTATED}")), ROTATED_LOG));
    }
    needs
}

/// Fails, naming each path and what is wrong, unless the service account has what `run` opens by the DACLs: an allow
/// for the account or for a credited group, and no deny ACE of any kind. `run --check` calls it, with the paths of the
/// binary that the service will run.
pub fn check(paths: &Paths, exe: &Path, frpc: &Path) -> Result<()> {
    let account = Sid::parse(&account::ensure(service::ACCOUNT)?.sid()).context("the service account's SID")?;
    let mut holders = vec![(account, service::ACCOUNT)];
    for (sid, name) in CREDITED {
        holders.push((Sid::parse(sid).with_context(|| format!("the SID of {name}"))?, name));
    }
    let who = Principals { holders };
    let problems: Vec<String> = opens(paths, exe, frpc)
        .iter()
        .filter_map(|need| problem(need, &who).map(|problem| format!("{}: {problem}", need.path.display())))
        .collect();
    ensure!(problems.is_empty(), "{}", problems.join("\n"));
    Ok(())
}

/// Why the service account cannot have what `run` needs of `need.path`, in the user's words.
fn problem(need: &Need, who: &Principals) -> Option<String> {
    explain(need, who, security::aces_of(&need.path))
}

/// `problem` for what reading `need.path`'s DACL gave.
fn explain(need: &Need, who: &Principals, dacl: io::Result<Dacl>) -> Option<String> {
    let account = service::ACCOUNT;
    let (needs, verb) = need.itself;
    let dacl = match dacl {
        Ok(dacl) => dacl,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return (!need.made_by_run).then(|| format!("it is missing, and {account} needs to {verb} it"));
        }
        Err(err) => {
            return Some(format!(
                "its ACL cannot be read to see whether {account} may {verb} it: {err}"
            ));
        }
    };
    let (inherits, files_verb) = need.files.unwrap_or_default();
    let groups = || {
        let names: Vec<&str> = who.holders.iter().skip(1).map(|(_, name)| *name).collect();
        names.join(", ")
    };
    let left_out = match dacl.left_out {
        0 => String::new(),
        1 => " This check does not count conditional, object or compound allow ACEs; its ACL has one.".to_string(),
        n => format!(" This check does not count conditional, object or compound allow ACEs; its ACL has {n}."),
    };
    Some(match barrier_of(&dacl.aces, who, needs, inherits)? {
        Barrier::Denied(by) => {
            format!("an ACE in its ACL denies access to {by}. {account} must not be denied anything: remove that ACE.")
        }
        Barrier::NotAllowed => format!(
            "{account} cannot {verb} it: no ACE in its ACL allows that to {account} or to a group it always \
             belongs to ({}). Allow {account} to {verb} it.{left_out}",
            groups()
        ),
        Barrier::NotInherited => format!(
            "the files {account} makes in it would not get the right to {files_verb} themselves: no ACE in its ACL \
             that files inherit allows that to {account} or to a group it always belongs to ({}). Add an allow for \
             {account} that files inherit.{left_out}",
            groups()
        ),
    })
}

/// What stands between the service and the rights it needs.
#[derive(Debug)]
pub enum Barrier {
    /// An ACE denies this account or group something: `Sid::label` of its SID, which says which SIDs are named and
    /// which are shown as text. Any deny ACE is a barrier, whoever it names and whatever it denies.
    Denied(String),
    /// The allow ACEs for the service and its groups do not add up to the rights.
    NotAllowed,
    /// The allows that files inherit do not add up to what the files `run` makes there need.
    NotInherited,
}

/// What stands in the way of `who` having `needs` of an object and its files `inherits`, by the DACL `aces`: any deny
/// ACE (inherit-only too: the contents get it), allows for `who` not adding up to `needs`, or those that files inherit
/// (plus CREATOR OWNER's: the service owns what it makes) not adding up to `inherits`. A sufficient condition, not
/// AccessCheck: it refuses a DACL whose order would let the account through, and ignores the owner and privileges.
fn barrier_of(aces: &[Ace], who: &Principals, needs: u32, inherits: u32) -> Option<Barrier> {
    let (mut allowed, mut inherited) = (0, 0);
    for ace in aces {
        if !ace.allows {
            return Some(Barrier::Denied(ace.sid.label()));
        }
        let rights = file_rights(ace.mask);
        if who.holders.iter().any(|(sid, _)| *sid == ace.sid) {
            if !ace.inherit_only {
                allowed |= rights;
            }
            if ace.object_inherit {
                inherited |= rights;
            }
        } else if ace.object_inherit && ace.sid == *CREATOR_OWNER_SID {
            // CREATOR OWNER is nothing in the directory itself: not counted in `allowed`.
            inherited |= rights;
        }
    }
    if allowed & needs != needs {
        Some(Barrier::NotAllowed)
    } else {
        (inherited & inherits != inherits).then_some(Barrier::NotInherited)
    }
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
