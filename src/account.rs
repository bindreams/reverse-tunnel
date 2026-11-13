//! The service account of an install: on Linux and macOS a system account with a group of its own; on Windows the
//! virtual account `NT SERVICE\reverse-tunnel`, which SCM makes with the service and removes with it.

use anyhow::{Context, Result};

#[cfg(unix)]
use crate::command::run;
#[cfg(windows)]
use crate::security::Sid;

/// The ids of the account.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

/// The account's SID, which names it in an ACL before SCM has made it.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// The five sub-authorities that follow `S-1-5-80`.
    hash: [u32; 5],
}

#[cfg(unix)]
pub fn lookup(name: &str) -> Option<Account> {
    let user = uzers::get_user_by_name(name)?;
    Some(Account {
        uid: user.uid(),
        gid: user.primary_group_id(),
    })
}

/// The account `name`, created if it is missing, and completed if a failed run left part of it.
#[cfg(unix)]
pub fn ensure(name: &str) -> Result<Account> {
    complete(name)?;
    lookup(name).with_context(|| format!("created {name}, but the system does not list it"))
}

#[cfg(windows)]
impl Account {
    /// The virtual account of the service `service`: its SID is `S-1-5-80-` and the SHA-1 of the upper-cased name, in
    /// UTF-16, as five little-endian numbers (what `sc showsid` prints).
    pub fn of_service(service: &str) -> Account {
        use sha1::{Digest, Sha1};

        let name: Vec<u8> = service
            .to_uppercase()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let digest = Sha1::digest(name);
        Account {
            hash: std::array::from_fn(|at| u32::from_le_bytes(digest[at * 4..at * 4 + 4].try_into().unwrap())),
        }
    }

    pub fn sid(&self) -> String {
        let [a, b, c, d, e] = self.hash;
        format!("S-1-5-80-{a}-{b}-{c}-{d}-{e}")
    }

    /// The same SID in its binary form.
    pub fn to_sid(&self) -> Sid {
        let [a, b, c, d, e] = self.hash;
        Sid::nt(&[80, a, b, c, d, e])
    }
}

/// The virtual account `NT SERVICE\<service>`. SCM makes it with the service, but it is named by its SID.
#[cfg(windows)]
pub fn ensure(name: &str) -> Result<Account> {
    let service = name
        .strip_prefix("NT SERVICE\\")
        .with_context(|| format!("{name} is not a virtual service account"))?;
    Ok(Account::of_service(service))
}

/// Nothing to remove: SCM removes the account with the service.
#[cfg(windows)]
pub fn remove(_name: &str) -> Result<()> {
    Ok(())
}

// Commands are named by absolute path: root's `PATH` may lack `sbin` (`su` without `-`).

/// Creates the account `name` unless it is there, with a group of its own, or into that group if a failed run left it.
#[cfg(target_os = "linux")]
fn complete(name: &str) -> Result<()> {
    if lookup(name).is_none() {
        let group: &[&str] = if uzers::get_group_by_name(name).is_some() {
            &["--gid", name]
        } else {
            &["--user-group"]
        };
        let mut args = vec![
            "/usr/sbin/useradd",
            "--system",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
        ];
        args.extend(group);
        args.push(name);
        run(&args)?;
    }
    Ok(())
}

/// Removes the account and its group, if present.
#[cfg(target_os = "linux")]
pub fn remove(name: &str) -> Result<()> {
    if lookup(name).is_some() {
        run(&["/usr/sbin/userdel", name])?;
    }
    // `userdel` keeps the group when another user has it as primary group or the system does not delete user groups,
    // and a failed run can leave the group alone.
    if uzers::get_group_by_name(name).is_some() {
        run(&["/usr/sbin/groupdel", name])?;
    }
    Ok(())
}

/// Writes every attribute of the user and the group, which `dscl -create` does whether or not the record exists, so a
/// run that stopped midway is finished by the next. An account that exists keeps its id; a new one gets a free id,
/// and another if someone else took it meanwhile. Whether it exists is read from the local directory, not from
/// `getpwnam`, whose cache can answer for an account just removed.
#[cfg(target_os = "macos")]
fn complete(name: &str) -> Result<()> {
    let existing = listed_ids("/Users", "UniqueID", ".")?
        .into_iter()
        .find_map(|(holder, id)| (holder == name).then_some(id));
    let mut id = match existing {
        Some(id) => id,
        None => free_id()?,
    };
    loop {
        let (user, group, value) = (format!("/Users/{name}"), format!("/Groups/{name}"), id.to_string());
        let (user, group, value) = (user.as_str(), group.as_str(), value.as_str());
        for [record, key, value] in [
            [group, "PrimaryGroupID", value],
            [user, "UniqueID", value],
            [user, "PrimaryGroupID", value],
            [user, "UserShell", "/usr/bin/false"],
            [user, "NFSHomeDirectory", "/var/empty"],
            [user, "Password", "*"],
        ] {
            run(&["/usr/bin/dscl", ".", "-create", record, key, value])?;
        }
        // Choosing and writing an id are two commands, so ask again who holds it.
        if existing.is_some() || !ids_in_use()?.iter().any(|(holder, held)| *held == id && holder != name) {
            return Ok(());
        }
        id = free_id()?;
    }
}

/// Removes the user and the group, each if present.
#[cfg(target_os = "macos")]
pub fn remove(name: &str) -> Result<()> {
    for records in ["/Users", "/Groups"] {
        if run(&["/usr/bin/dscl", ".", "-list", records])?
            .lines()
            .any(|line| line == name)
        {
            run(&["/usr/bin/dscl", ".", "-delete", &format!("{records}/{name}")])?;
        }
    }
    Ok(())
}

/// The name and `key` (an id) of every record of `records` that the directory node `node` lists.
#[cfg(target_os = "macos")]
fn listed_ids(records: &str, key: &str, node: &str) -> Result<Vec<(String, u32)>> {
    let listing = run(&["/usr/bin/dscl", node, "-list", records, key])?;
    Ok(listing
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.to_string(), fields.next_back()?.parse().ok()?))
        })
        .collect())
}

/// Every user and group the system knows, local or from a directory service, with its id.
#[cfg(target_os = "macos")]
fn ids_in_use() -> Result<Vec<(String, u32)>> {
    let mut used = listed_ids("/Users", "UniqueID", "/Search")?;
    used.extend(listed_ids("/Groups", "PrimaryGroupID", "/Search")?);
    Ok(used)
}

/// The lowest id from 200 to 399, which Apple sets aside for system accounts, that is neither a user's nor a group's.
#[cfg(target_os = "macos")]
fn free_id() -> Result<u32> {
    let used: Vec<u32> = ids_in_use()?.into_iter().map(|(_, id)| id).collect();
    (200..400)
        .find(|id| !used.contains(id))
        .context("every system id from 200 to 399 is taken")
}

#[cfg(all(test, windows))]
#[path = "account_tests.rs"]
mod tests;
