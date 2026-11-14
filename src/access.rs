//! Windows: whether the service account has what `run` opens, judged from each path's DACL alone.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES,
};

use crate::account;
use crate::download;
use crate::logfile::ROTATED;
use crate::paths::{FRPC_CONFIG, LOG_FRPC, LOG_SUPERVISOR, Paths};
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

/// CREATOR OWNER: in an ACE that files inherit, whoever makes the file. The service owns what it makes, which the
/// platform test of `CREDITED` asserts of `supervisor.log`.
const CREATOR_OWNER: &str = "S-1-3-0";
static CREATOR_OWNER_SID: LazyLock<Sid> =
    LazyLock::new(|| Sid::parse(CREATOR_OWNER).expect("CREATOR_OWNER is a valid SID"));

/// A right that `run` needs, and the word for it in a failure.
pub type Right = (u32, &'static str);
const READ: Right = (FILE_GENERIC_READ, "read");
const RUN: Right = (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, "read and run");
/// Of the log directory itself: `run` makes files there, and renames a log there (rotation).
const MAKE_FILES: Right = (FILE_ADD_FILE, "create files in");
/// Of a file `run` makes in the log directory, which it gets from the directory: `run` writes each, `frpc` reads
/// `frpc.toml`, and a rotation renames a log, which needs DELETE on it and on the old log it replaces.
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

/// The SIDs that count in a check: the service account first, then the groups it always belongs to, each with its name.
pub struct Principals {
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

/// Every path `run` opens, with what it needs of each; `exe` is the binary the service will run: the installed one, or,
/// at an `install`, the staged copy, which gets the access that `install` gives the installed binary (it inherits the
/// bin dir's ACL, as the installed one is made to). `run` lists no directory, and Windows lets a service through a
/// directory it has no right to (SeChangeNotifyPrivilege, enabled in the service's token: asserted by the platform test
/// of `CREDITED`), so a directory is here only where `run` makes files: the log directory, where it creates
/// `supervisor.log`, `frpc.log` and `frpc.toml`, appends to the logs and rotates each to `<log>.1`. Those files are
/// listed too, for each that already exists.
pub fn opens(paths: &Paths, exe: &Path) -> Vec<Need> {
    let logs = &paths.log_dir;
    let mut needs = vec![
        Need::of(exe.to_path_buf(), RUN),
        Need::of(download::tools(paths).frpc, RUN),
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
/// for the account or for a credited group, and no deny ACE of any kind. `run --check` as the caller cannot show this:
/// an administrator reads what the account cannot.
pub fn check(paths: &Paths, exe: &Path) -> Result<()> {
    let account = Sid::parse(&account::ensure(service::ACCOUNT)?.sid()).context("the service account's SID")?;
    let mut holders = vec![(account, service::ACCOUNT)];
    for (sid, name) in CREDITED {
        holders.push((Sid::parse(sid).with_context(|| format!("the SID of {name}"))?, name));
    }
    let who = Principals { holders };
    let problems: Vec<String> = opens(paths, exe)
        .iter()
        .filter_map(|need| problem(need, &who).map(|problem| format!("{}: {problem}", need.path.display())))
        .collect();
    ensure!(problems.is_empty(), "{}", problems.join("\n"));
    Ok(())
}

/// Why the service account cannot have what `run` needs of `need.path`, in the user's words.
fn problem(need: &Need, who: &Principals) -> Option<String> {
    let account = service::ACCOUNT;
    let (needs, verb) = need.itself;
    let aces = match security::aces_of(&need.path) {
        Ok(aces) => aces,
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
    Some(match barrier_of(&aces, who, needs, inherits)? {
        Barrier::Denied(by) => {
            format!("an ACE in its ACL denies access to {by}. {account} must not be denied anything: remove that ACE.")
        }
        Barrier::NotAllowed => format!(
            "{account} cannot {verb} it: no ACE in its ACL allows that to {account} or to a group it always \
             belongs to ({}). Allow {account} to {verb} it.",
            groups()
        ),
        Barrier::NotInherited => format!(
            "the files {account} makes in it would not get the right to {files_verb} themselves: no ACE in its ACL \
             that files inherit allows that to {account} or to a group it always belongs to ({}). Add an allow for \
             {account} that files inherit.",
            groups()
        ),
    })
}

/// What stands between the service and the rights it needs.
#[derive(Debug)]
pub enum Barrier {
    /// An ACE denies this account or group something: its name (`Sid::label`), or its SID where it is not asked for a
    /// name (a SID of another domain: every domain account and group) or has none. Any deny ACE is a barrier, whoever
    /// it names and whatever it denies.
    Denied(String),
    /// The allow ACEs for the service and its groups do not add up to the rights.
    NotAllowed,
    /// The allows that files inherit do not add up to what the files `run` makes there need.
    NotInherited,
}

/// What stands in the way of `who` having all of `needs` of an object, and its files all of
/// `inherits`, as the DACL `aces` gives it: there is no deny ACE at all (inherit-only ones too, which the object's
/// contents get), the allows for `who` add up to `needs`, and those that files inherit add up to `inherits`. Allows
/// for the object's contents only count for nothing towards `needs`; an allow for CREATOR OWNER that files inherit
/// counts towards `inherits` (the service owns what it makes). A sufficient condition, not AccessCheck: it
/// refuses a DACL whose order would let the account through, and ignores the owner and privileges.
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
            // Files the service makes are its own, which CREATOR OWNER becomes in them. It is nothing in the
            // directory itself, so it adds nothing to `allowed`.
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
