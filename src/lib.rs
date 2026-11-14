#[cfg(windows)]
pub mod access;
pub mod account;
pub mod command;
pub mod config;
pub mod download;
pub mod files;
pub mod frpc;
// Shared with `tests/`, which uses all of it.
#[cfg(all(test, windows))]
#[allow(dead_code)]
#[path = "../tests/support/held.rs"]
mod held;
pub mod install;
pub mod join;
#[cfg(windows)]
pub mod leftovers;
pub mod logfile;
pub mod ops;
pub mod output;
pub mod paths;
#[cfg(windows)]
pub mod processes;
pub mod report;
#[cfg(windows)]
pub mod schtasks;
#[cfg(windows)]
pub mod security;
pub mod service;
pub mod supervisor;
#[cfg(windows)]
pub mod system_path;
#[cfg(all(test, unix))]
mod test_stub;
pub mod upgrade;
