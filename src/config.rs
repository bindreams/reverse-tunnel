use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{Deserializer, Error, MapAccess, Visitor};

/// The frps control port, TCP and UDP; shared with `server/compose.yaml`.
pub const CONTROL_PORT: u16 = 7000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub host: String,
    /// The tunnel domain T.
    pub bridge: String,
    pub default: Option<String>,
    #[serde(deserialize_with = "unique_services")]
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
        // Windows editors write a leading BOM.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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

/// Collects the services into a map, failing with the name on a repeat. Names compare as `Config` sees them, so `22`
/// and `'22'` collide.
fn unique_services<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<String, Service>, D::Error> {
    struct Services;

    impl<'de> Visitor<'de> for Services {
        type Value = BTreeMap<String, Service>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a map of services")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut services = BTreeMap::new();
            while let Some((name, service)) = map.next_entry::<String, Service>()? {
                if services.contains_key(&name) {
                    return Err(A::Error::custom(format!("duplicate service {name:?}")));
                }
                services.insert(name, service);
            }
            Ok(services)
        }
    }

    deserializer.deserialize_map(Services)
}

/// One DNS label (lowercase, digits, inner hyphens, at most 63 characters, no `--` at positions 3-4). Mirrors
/// `server/ctl/names.py`.
pub fn valid_label(s: &str) -> bool {
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
