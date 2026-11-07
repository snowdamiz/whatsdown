// Test-only I/O adapter around the production host. Core, SDK and bank calls
// are supplied by submit-correlation.py through this process's standard input.
#[path = "../../apps/desktop/src-tauri/src/bounty.rs"]
mod bounty;
use std::io::{self, BufRead, Write};
fn decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap()).collect()
}
fn encode(input: &[u8]) -> String { input.iter().map(|byte| format!("{byte:02x}")).collect() }
fn exchange(kind: &str, name: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    println!("{kind} {name} {}", encode(input));
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap();
    match line.trim().strip_prefix("ERR ") {
        Some(error) => Err(error.to_owned()),
        None => Ok(decode(line.trim())),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = bounty::movement(&decode(&args[1]), args[2].as_bytes(),
        |name, request| exchange("MESH", name, request),
        |operation, request| exchange("SDK", &operation.to_string(), request));
    match result {
        Ok(value) => println!("DONE OK {}", encode(&value)),
        Err(error) => println!("DONE ERR {error}"),
    }
}
