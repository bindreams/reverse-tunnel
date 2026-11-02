//! The service account of a Linux or macOS install: a system account with a group of its own.

use anyhow::{Context, Result, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

pub fn lookup(name: &str) -> Option<Account> {
    let user = uzers::get_user_by_name(name)?;
    Some(Account {
        uid: user.uid(),
        gid: user.primary_group_id(),
    })
}

/// The account `name`, created if it is missing, and completed if a failed run left part of it.
pub fn ensure(name: &str) -> Result<Account> {
    complete(name)?;
    lookup(name).with_context(|| format!("created {name}, but the system does not list it"))
}

/// Runs `args[0]` with the rest, and returns its output.
fn run(args: &[&str]) -> Result<String> {
    let out = cosca::run(args.iter().copied())
        .output()
        .with_context(|| format!("running {}", args[0]))?;
    ensure!(
        out.status.success(),
        "`{}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
