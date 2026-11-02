use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

/// The frps control port, TCP and UDP; shared with `server/compose.yaml`.
pub const CONTROL_PORT: u16 = 7000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub host: String,
    /// The tunnel domain T.
    pub bridge: String,
    pub default: Option<String>,
    pub services: BTreeMap<String, Service>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub port: u16,
    pub r#type: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tcp,
    Http,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        // Parsing into a map keeps the last duplicate silently, and serde_with's `MapPreventDuplicates`
        // does not name the key. A generic `Value` names it and covers every mapping.
        yaml_serde::from_str::<yaml_serde::Value>(text)?;
        let cfg: Config = yaml_serde::from_str(text)?;
        ensure!(valid_label(&cfg.host), "host {:?} is not a valid name", cfg.host);
        ensure!(
            valid_domain(&cfg.bridge),
            "bridge {:?} is not a valid domain",
            cfg.bridge
        );
        for (name, service) in &cfg.services {
            ensure!(valid_label(name), "service name {name:?} is not a valid name");
            ensure!(service.port != 0, "service {name:?}: port must be 1 to 65535");
        }
        if let Some(default) = &cfg.default {
            ensure!(
                cfg.services.contains_key(default),
                "default service {default:?} is not in services"
            );
        }
        Ok(cfg)
    }
}

/// One DNS label: lowercase letters, digits and inner hyphens, at most 63 characters, and no hyphens
/// at the third and fourth position (reserved by DNS, refused by ACME CAs). Mirrors `server/ctl/names.py`.
fn valid_label(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.get(2..4) != Some("--")
}

/// A tunnel domain: at least two valid labels, at most 125 characters (so `s.h.T` fits DNS's 253), no trailing dot.
pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 125 && domain.split('.').count() >= 2 && domain.split('.').all(valid_label)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
