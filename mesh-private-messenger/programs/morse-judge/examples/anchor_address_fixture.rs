//! Independent public test addresses. This prints fixtures, never submits a
//! transaction or uses a wallet. Compare these with the Mesh RPC test.
use solana_address::Address;
use solana_sha256_hasher::hash;

fn main() {
    let program = Address::default();
    for name in ["morse-main", "morse-canary"] {
        let log_id = hash(name.as_bytes()).to_bytes();
        for kind in [b"log".as_slice(), b"ring"] {
            let (address, bump) = Address::find_program_address(&[kind, name.as_bytes()], &program);
            println!(
                "{name} {} {address} {bump}",
                std::str::from_utf8(kind).unwrap()
            );
        }
        for generation in [1u16, 7, 65535] {
            let (address, bump) = Address::find_program_address(
                &[b"witness-set", &log_id, &generation.to_le_bytes()],
                &program,
            );
            println!("{name} set {generation} {address} {bump}");
        }
    }
}
