use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

const CODE: &str = include_str!("../server/testdata/join-code.txt");

fn code_for(json: &str) -> String {
    format!("rt1:{}", URL_SAFE_NO_PAD.encode(json))
}

#[test]
fn join_decodes_python_fixture() {
    let info = decode(CODE).unwrap();
    assert_eq!(info.domain, "tunnel.example.test");
    assert_eq!(info.token, "0".repeat(64));
    assert_eq!(info.cert_pem, include_str!("../server/testdata/bridge.pem"));
}

#[test]
fn join_ignores_whitespace() {
    let code = CODE.trim();
    let chunks: Vec<&str> = code
        .as_bytes()
        .chunks(7)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let pasted = format!("  {}\r\n\t", chunks.join(" \n"));
    assert_eq!(decode(&pasted).unwrap().token, decode(code).unwrap().token);
}

#[test]
fn join_rejects_malformed_codes() {
    let good = r#"{"domain": "tunnel.example.test", "token": "t", "cert": "c"}"#;
    let cases = [
        ("wrong prefix", CODE.trim().replacen("rt1:", "rt2:", 1)),
        ("bad base64", "rt1:!!!!".to_string()),
        ("padded", format!("{}=", CODE.trim())),
        (
            "missing field",
            code_for(r#"{"domain": "tunnel.example.test", "token": "t"}"#),
        ),
        (
            "invalid domain",
            code_for(&good.replace("tunnel.example.test", "Not_A_Domain")),
        ),
    ];
    for (name, code) in cases {
        assert!(decode(&code).is_err(), "{name} was accepted");
    }
    assert!(decode(&code_for(good)).is_ok());
}

#[test]
fn token_hash_vector() {
    assert_eq!(
        token_hash(&"0".repeat(64)),
        "sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55"
    );
}
