//! The service account of a Linux or macOS install: a system account with a group of its own.

use anyhow::{Context, Result, ensure};

/// The ids of an account.
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

/// Creates the account `name` with its group, unless `existing` says it is there: one command makes both.
#[cfg(target_os = "linux")]
fn complete(name: &str, existing: Option<Account>) -> Result<()> {
    if existing.is_none() {
        run(&[
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            name,
        ])?;
    }
    Ok(())
}

/// Removes the account and its group, if present.
#[cfg(target_os = "linux")]
pub fn remove(name: &str) -> Result<()> {
    if lookup(name).is_some() {
        run(&["/usr/sbin/userdel", name])?;
    }
    Ok(())
}

// macOS ================================================================================================================

/// Writes every attribute of the user and the group, which `dscl -create` does whether or not the record exists, so a
/// run that stopped midway is finished by the next. An account that exists keeps its id.
#[cfg(target_os = "macos")]
fn complete(name: &str, existing: Option<Account>) -> Result<()> {
    let id = match existing {
        Some(account) => account.uid,
        None => free_id()?,
    }
    .to_string();
    let (user, group) = (format!("/Users/{name}"), format!("/Groups/{name}"));
    let (user, group, id) = (user.as_str(), group.as_str(), id.as_str());
    for [record, key, value] in [
        [group, "PrimaryGroupID", id],
        [user, "UniqueID", id],
        [user, "PrimaryGroupID", id],
        [user, "UserShell", "/usr/bin/false"],
        [user, "NFSHomeDirectory", "/var/empty"],
        [user, "Password", "*"],
    ] {
        run(&["/usr/bin/dscl", ".", "-create", record, key, value])?;
    }
    Ok(())
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

/// The lowest id from 200 to 399, which Apple sets aside for system accounts, that is neither a user's nor a group's.
#[cfg(target_os = "macos")]
fn free_id() -> Result<u32> {
    let mut used = std::collections::BTreeSet::new();
    for (records, key) in [("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")] {
        for line in run(&["/usr/bin/dscl", ".", "-list", records, key])?.lines() {
            used.extend(
                line.split_whitespace()
                    .next_back()
                    .and_then(|id| id.parse::<u32>().ok()),
            );
        }
    }
    (200..400)
        .find(|id| !used.contains(id))
        .context("every system id from 200 to 399 is taken")
}
