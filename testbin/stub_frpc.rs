//! Stands in for frpc in `tests/supervisor.rs`. What it does is the text of `<this exe>.mode`:
//!
//! - `exit <code>`: print a line to stderr and exit.
//! - `record <code> <file>`: write `ARG <argument>` and `ENV <name>=<value>` lines, then `TOML` and the `-c` file's
//!   text, to `<file>`, then exit.
//! - `hold <addr>`: connect to `<addr>` and stay until the peer closes it.

use std::io::Read;
use std::net::TcpStream;
use std::process::exit;
use std::{env, fs};

fn main() {
    let mode = fs::read_to_string(env::current_exe().unwrap().with_extension("mode")).unwrap();
    let words: Vec<&str> = mode.trim_end().splitn(3, ' ').collect();
    match words[..] {
        ["exit", code] => {
            eprintln!("stub frpc: failing");
            exit(code.parse().unwrap());
        }
        ["record", code, file] => {
            let args: Vec<String> = env::args().skip(1).collect();
            let config = args
                .iter()
                .position(|arg| arg == "-c")
                .map(|at| fs::read_to_string(&args[at + 1]).unwrap());
            let mut out = String::new();
            args.iter().for_each(|arg| out += &format!("ARG {arg}\n"));
            env::vars().for_each(|(name, value)| out += &format!("ENV {name}={value}\n"));
            fs::write(file, format!("{out}TOML\n{}", config.unwrap_or_default())).unwrap();
            exit(code.parse().unwrap());
        }
        ["hold", addr] => {
            TcpStream::connect(addr).unwrap().read_to_end(&mut Vec::new()).unwrap();
        }
        _ => panic!("unknown mode {mode:?}"),
    }
}
