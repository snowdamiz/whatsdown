from Transparency.Config import SecurityConfig, decode_security_config
from Transparency.Fork import ForkProof, ForkTarget
from Transparency.Merkle import sign_tree_checkpoint_for, TransparencyCheckpoint
from Tests.GroupConsistencySupport import signing_pair, wide
from Tests.Support import repeated

pub fn filing_fixture() -> Result<(ForkProof, SecurityConfig), String> do
  let signer = signing_pair()?
  let first = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    Crypto.sha256(Bytes.from_utf8("private")),
    repeated(0, 32)?,
    wide(1000)?)?
  let second = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(2)?,
    Crypto.sha256(Bytes.from_utf8("public")),
    repeated(0, 32)?,
    wide(2000)?)?
  let proof = ForkProof {
    kind: 1,
    finder: repeated(7, 32)?,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: [],
    contradiction: None
  }
  let frame = String.join([
      "5",
      Bytes.to_hex(signer.public_key.bytes),
      String.repeat("22", 32),
      "8",
      "1",
      "1",
      "a #{String.repeat("09", 32)} Fixture",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "1",
      "1",
      "a #{String.repeat("09", 32)} Fixture",
      String.repeat("1", 32),
      "morse-main",
      Bytes.to_base58(repeated(9, 32)?),
      "3",
      "https://relay-one.example",
      "https://relay-two.example",
      "https://relay-three.example"
    ],
    "\n")
  Ok((proof, decode_security_config(Bytes.from_utf8(frame))?))
end
