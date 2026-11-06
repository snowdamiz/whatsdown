from Transparency.TokenBurnRead import TokenBurnReadPins
from Solana.Read import AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

pub struct TokenBurnCarryFixture do
  pins :: TokenBurnReadPins
  epoch :: U64
  snapshot :: OptionalAccountSlicesAtSlot
end

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

pub fn token_burn_carry_fixture(label :: String) -> TokenBurnCarryFixture!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", ""))?)?
  let entries = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(entries)? do
    let item = Json.array_get(entries, index)?
    if text(item, "name")? == label do
      let accounts = Json.object_get(item, "accounts")?
      let snapshot = OptionalAccountSlicesAtSlot {
        slot: U64.parse(text(item, "context_slot")?)?,
        accounts: for account_index in 0..Json.array_length(accounts)? do
          let a = Json.array_get(accounts, account_index)?
          case Json.object_get(a, "missing") do
            Ok(_) -> None
            Err(_) -> Some(AccountSlice {
              space: U64.parse(text(a, "space")?)?,
              info: AccountInfo {
                owner: pubkey(text(a, "owner")?)?,
                data: Bytes.from_hex(text(a, "data_hex")?)?,
                lamports: U64.parse(text(a, "lamports")?)?,
                rent_epoch: U64.parse("0")?,
                executable: Json.as_bool(Json.object_get(a, "executable")?)?
              }
            })
          end
        end
      }
      return Ok(TokenBurnCarryFixture {
        pins: TokenBurnReadPins {
          program: pubkey(text(item, "program")?)?,
          governance: pubkey(text(item, "governance")?)?,
          program_slot: U64.parse(text(item, "program_slot")?)?,
          usdc: pubkey(text(item, "usdc")?)?,
          treasury: pubkey(text(item, "treasury")?)?,
          factory: pubkey(text(item, "factory")?)?
        },
        epoch: U64.parse(text(item, "epoch")?)?,
        snapshot: snapshot
      })
    end
  end
  Err("missing_burn_carry_fixture")
end
