use anyhow::Result;
use sha2::{Digest, Sha256};

fn expected_digest<'a>(_sums: &'a str, _asset: &str) -> Result<&'a str> {
    anyhow::bail!("todo")
}

fn fetch_release(_releases: &str, _target: &str) -> Result<Vec<u8>> {
    anyhow::bail!("todo")
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
