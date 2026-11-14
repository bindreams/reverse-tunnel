//! Windows: leftovers. Windows refuses to delete or replace a running image (access denied) and allows renaming it, so
//! such a file is renamed aside instead: a leftover is `.reverse-tunnel.<id>.<the name it had>` in the folder that
//! holds the bin dir (see `dir`), which only administrators can write to. Every `install` and `upgrade` deletes the
//! leftovers it can (see `delete_what_can_be`), and the removal's task deletes the rest (see
//! `schtasks::removal_script`).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::files::{
    OpenElsewhere, hex_of_random_bytes, is_access_denied, is_not_found, remove_file, require_regular_file,
};
use crate::paths::Paths;
use crate::service;

/// What a leftover's name starts with.
const PREFIX: &str = ".reverse-tunnel.";

/// The leftover that renames the file called `original`, called `id`.
pub fn name(id: &str, original: &OsStr) -> OsString {
    let mut name = OsString::from(format!("{PREFIX}{id}."));
    name.push(original);
    name
}

/// The pattern that every leftover in `dir` matches, for `cmd`.
pub fn pattern(dir: &Path) -> PathBuf {
    dir.join(format!("{PREFIX}*"))
}

/// What follows `PREFIX` in `name`, which `cmd` matches whatever the case.
fn after_prefix(name: &str) -> Option<&str> {
    let (prefix, rest) = (name.get(..PREFIX.len())?, name.get(PREFIX.len()..)?);
    prefix.eq_ignore_ascii_case(PREFIX).then_some(rest)
}

/// Whether the file called `name` is a leftover: whether `pattern` matches it.
pub fn is_leftover(name: &str) -> bool {
    after_prefix(name).is_some()
}

/// Whether the file called `name` is a leftover of a file that was called `original`.
pub fn is_leftover_of(name: &str, original: &str) -> bool {
    kept_name(name).is_some_and(|kept| kept.eq_ignore_ascii_case(original))
}

/// The name that the leftover called `name` had, if it is a leftover.
pub fn kept_name(name: &str) -> Option<&str> {
    // The id is hex, so the first dot ends it.
    after_prefix(name)?.split_once('.').map(|(_id, kept)| kept)
}

/// The folder that holds the bin dir, where leftovers go.
pub fn dir(paths: &Paths) -> Result<&Path> {
    paths.bin_dir.parent().context("the bin dir has no parent")
}

/// Renames the file `path` into `leftovers`, keeping its name, and returns the new path. Only a regular file is moved
/// aside, since only a file is an image and the sweeps never delete anything else: any other `path` is an error naming
/// it, and nothing is moved. A `path` that another process holds open waits (see `OpenElsewhere`).
pub fn move_aside(path: &Path, leftovers: &Path) -> Result<PathBuf> {
    require_regular_file(path, "not moved aside")?;
    let original = path.file_name().context("the file has no name")?;
    let to = leftovers.join(name(&hex_of_random_bytes::<16>()?, original));
    let mut wait = OpenElsewhere::default();
    while let Err(err) = fs::rename(path, &to) {
        if !wait.waited_for(path, &err) {
            return Err(err).with_context(|| format!("moving it to {}", to.display()));
        }
    }
    Ok(to)
}

/// The error for a delete or replace that Windows `refused` and whose move aside (`moving`) failed too. It has both OS
/// answers, and `refused` stays the source, so `is_access_denied` and `root_cause` still reach it.
pub fn refused_and_not_moved(refused: anyhow::Error, moving: &anyhow::Error) -> anyhow::Error {
    refused.context(format!("moving it aside failed ({moving:#}), after this refusal"))
}

/// The leftovers, sorted by path.
pub fn images(paths: &Paths) -> Result<Vec<PathBuf>> {
    let dir = dir(paths)?;
    let mut images = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if is_leftover(&entry.file_name().to_string_lossy()) {
            images.push(entry.path());
        }
    }
    images.sort();
    Ok(images)
}

/// The leftovers of the installed binary: of the file on the `PATH` first, then of the service images (see
/// `service::image`), each sorted by path. Any of them can be run with `uninstall`, and a removal that ran from one may
/// have left it as the only copy.
pub fn images_of_the_binary(paths: &Paths) -> Result<Vec<PathBuf>> {
    let binary = service::exe(paths);
    let binary = binary.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let (mut of_binary, mut of_images) = (Vec::new(), Vec::new());
    for image in images(paths)? {
        let name = image.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if is_leftover_of(name, binary) {
            of_binary.push(image);
        } else if kept_name(name).is_some_and(service::is_image) {
            of_images.push(image);
        }
    }
    of_binary.extend(of_images);
    Ok(of_binary)
}

/// Whether `image`, a file to delete, is there: `false` if it is gone, an error if it is not a regular file.
pub fn is_there_to_delete(image: &Path) -> Result<bool> {
    match require_regular_file(image, "never deleted") {
        Ok(()) => Ok(true),
        Err(err) if is_not_found(&err) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Deletes the files `images`, all of them whatever happens to one, and moves none. A file that is gone is deleted.
/// Returns, one error for each, those that were kept, with the path and the cause: anything that is not a regular file,
/// which is never deleted, one that Windows refuses to delete, and one that fails for another reason.
pub fn delete_what_can_be(images: Vec<PathBuf>) -> Vec<anyhow::Error> {
    let mut kept = Vec::new();
    for image in images {
        match is_there_to_delete(&image) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                kept.push(err);
                continue;
            }
        }
        let Err(err) = remove_file(&image) else { continue };
        kept.push(if is_access_denied(&err) {
            err.context("Windows refused to delete it (access denied); each `install` tries again")
        } else {
            err
        });
    }
    kept
}

// Shared with `install`'s tests, which need the same installation.
#[cfg(test)]
#[path = "leftovers_tests.rs"]
pub(crate) mod tests;
