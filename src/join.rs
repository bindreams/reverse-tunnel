use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::valid_domain;

/// What a host learns from a join code.
#[derive(Debug, Deserialize)]
pub struct JoinInfo {
    pub domain: String,
    /// The shared frps token.
    pub token: String,
    #[serde(rename = "cert")]
    pub cert_pem: String,
}

/// Decodes `rt1:` and the unpadded base64url of the JSON object `server/ctl/joincode.py` emits.
/// ASCII whitespace anywhere in `code` is ignored, so a code pasted from chat still works.
pub fn decode(code: &str) -> Result<JoinInfo> {
    let code: String = code.split_ascii_whitespace().collect();
    let payload = code
        .strip_prefix("rt1:")
        .context("not a join code: it must start with rt1:")?;
    let json = URL_SAFE_NO_PAD
        .decode(payload)
        .context("join code is not valid base64")?;
    let info: JoinInfo = serde_json::from_slice(&json).context("join code holds no valid domain, token and cert")?;
    ensure!(
        valid_domain(&info.domain),
        "join code names an invalid domain {:?}",
        info.domain
    );
    Ok(info)
}

/// The registry form of a per-host token: `sha256:` and the hex digest of the token text.
pub fn token_hash(token_hex: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(token_hex)))
}

#[cfg(test)]
#[path = "join_tests.rs"]
mod tests;
