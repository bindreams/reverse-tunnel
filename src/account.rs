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

/// The account `name`, created if it is missing.
pub fn ensure(name: &str) -> Result<Account> {
    if let Some(account) = lookup(name) {
        return Ok(account);
    }
    create(name)?;
    lookup(name).with_context(|| format!("created {name}, but the system does not list it"))
}

/// Removes the account and its group, if present.
pub fn remove(name: &str) -> Result<()> {
    if lookup(name).is_some() {
        delete(name)?;
    }
    Ok(())
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

#[cfg(target_os = "linux")]
fn create(name: &str) -> Result<()> {
    let shell = "/usr/sbin/nologin";
    run(&[
        "useradd",
        "--system",
        "--user-group",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        shell,
        name,
    ])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn delete(name: &str) -> Result<()> {
    run(&["userdel", name])?;
    Ok(())
}

// macOS ================================================================================================================

#[cfg(target_os = "macos")]
fn create(name: &str) -> Result<()> {
    let id = free_id()?.to_string();
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
        run(&["dscl", ".", "-create", record, key, value])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn delete(name: &str) -> Result<()> {
    for record in [format!("/Users/{name}"), format!("/Groups/{name}")] {
        run(&["dscl", ".", "-delete", &record])?;
    }
    Ok(())
}

/// The lowest id from 200 to 399, which Apple sets aside for system accounts, that is neither a user's nor a group's.
#[cfg(target_os = "macos")]
fn free_id() -> Result<u32> {
    let mut used = std::collections::BTreeSet::new();
    for (records, key) in [("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")] {
        for line in run(&["dscl", ".", "-list", records, key])?.lines() {
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
