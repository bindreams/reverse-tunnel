//! Windows: whether the service account can read what `run` reads, judged from each path's DACL alone.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

use crate::account;
use crate::download;
use crate::paths::Paths;
use crate::security::{self, Ace, Sid};
use crate::service;

/// The groups, as (SID, name), that the token of the service always holds, enabled: the service is credited with what
/// an ACE gives them. Measured on CI from the running service's token (`tests/platform.rs`, the test of this list), not
/// from what an access check would do. The token also holds the logon session's SID and CONSOLE LOGON, which depend on
/// the session, and the High mandatory label, which is no group an ACE names.
pub const CREDITED: [(&str, &str); 7] = [
    ("S-1-1-0", "Everyone"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-6", "SERVICE"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-15", "This Organization"),
    ("S-1-2-0", "LOCAL"),
    ("S-1-5-80-0", "ALL SERVICES"),
];

/// A right that `run` needs, and the word for it in a failure.
type Right = (u32, &'static str);
const READ: Right = (FILE_GENERIC_READ, "read");
const ENTER: Right = (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, "read, list or run");

/// Everything `run` reads or enters, with what it needs of each.
fn reads(paths: &Paths) -> Vec<(PathBuf, Right)> {
    vec![
        (paths.bin_dir.clone(), ENTER),
        (download::tools(paths).frpc, ENTER),
        (paths.config_dir.clone(), ENTER),
        (paths.config_file(), READ),
        (paths.bridge_pem(), READ),
        (paths.secrets_dir.clone(), ENTER),
        (paths.bridge_token(), READ),
        (paths.host_token(), READ),
    ]
}

/// Fails, naming each path and what is wrong, unless the service account can read and enter what `run` reads, by the
/// DACLs: an allow for the account or for a credited group, and no deny for either. `run --check` as the caller cannot
/// show this: an administrator reads what the account cannot.
pub fn check(paths: &Paths) -> Result<()> {
    let account = Sid::parse(&account::ensure(service::ACCOUNT)?.sid()).context("the service account's SID")?;
    let mut who = vec![(account, service::ACCOUNT)];
    for (sid, name) in CREDITED {
        who.push((Sid::parse(sid).with_context(|| format!("the SID of {name}"))?, name));
    }
    let problems: Vec<String> = reads(paths)
        .into_iter()
        .filter_map(|(path, right)| problem(&path, right, &who).map(|problem| format!("{}: {problem}", path.display())))
        .collect();
    ensure!(problems.is_empty(), "{}", problems.join("\n"));
    Ok(())
}

/// Why the service account cannot have `right` of `path`, in the user's words.
fn problem(path: &std::path::Path, (needs, verb): Right, who: &[(Sid, &str)]) -> Option<String> {
    let account = service::ACCOUNT;
    let aces = match security::aces_of(path) {
        Ok(aces) => aces,
        Err(err) => {
            return Some(format!(
                "its ACL cannot be read to see whether {account} may {verb} it: {err}"
            ));
        }
    };
    Some(match barrier_of(&aces, who, needs)? {
        Barrier::Denied(name) => {
            format!("{account} cannot {verb} it: an ACE in its ACL denies that to {name}. Remove that ACE.")
        }
        Barrier::NotAllowed => {
            let groups: Vec<&str> = who.iter().skip(1).map(|(_, name)| *name).collect();
            format!(
                "{account} cannot {verb} it: no ACE in its ACL allows that to {account} or to a group it always \
                 belongs to ({}). Allow {account} to {verb} it.",
                groups.join(", ")
            )
        }
    })
}

/// What stands between the service and the rights it needs.
#[derive(Debug)]
pub enum Barrier {
    /// An ACE denies the named account or group some of the rights.
    Denied(String),
    /// The allow ACEs for the service and its groups do not add up to the rights.
    NotAllowed,
}

/// What stands in the way of `who` (each SID with its name) having all of `needs`, as the DACL `aces` gives it: the
/// allows for `who` must add up to `needs`, and no deny for `who` may name any of them. ACEs for the object's contents
/// only are left out. Not AccessCheck, which also weighs ACE order, the owner and privileges.
fn barrier_of(aces: &[Ace], who: &[(Sid, &str)], needs: u32) -> Option<Barrier> {
    let mut allowed = 0;
    for ace in aces.iter().filter(|ace| !ace.inherit_only) {
        let Some((_, name)) = who.iter().find(|(sid, _)| *sid == ace.sid) else {
            continue;
        };
        if ace.allows {
            allowed |= ace.mask;
        } else if ace.mask & needs != 0 {
            return Some(Barrier::Denied(name.to_string()));
        }
    }
    (allowed & needs != needs).then_some(Barrier::NotAllowed)
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
