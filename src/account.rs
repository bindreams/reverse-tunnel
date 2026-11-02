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
    complete(name, lookup(name))?;
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

/// Creates the account `name` unless `existing` says it is there, with a group of its own, or into that group if a
/// failed run left it.
#[cfg(target_os = "linux")]
fn complete(name: &str, existing: Option<Account>) -> Result<()> {
    if existing.is_none() {
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
/// and another if someone else took it meanwhile.
#[cfg(target_os = "macos")]
fn complete(name: &str, existing: Option<Account>) -> Result<()> {
    let mut id = match existing {
        Some(account) => account.uid,
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

/// Every user and group the system knows, local or from a directory service, with its id.
#[cfg(target_os = "macos")]
fn ids_in_use() -> Result<Vec<(String, u32)>> {
    let mut used = Vec::new();
    for (records, key) in [("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")] {
        for line in run(&["/usr/bin/dscl", "/Search", "-list", records, key])?.lines() {
            let mut fields = line.split_whitespace();
            if let (Some(name), Some(id)) = (fields.next(), fields.next_back().and_then(|id| id.parse().ok())) {
                used.push((name.to_string(), id));
            }
        }
    }
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
