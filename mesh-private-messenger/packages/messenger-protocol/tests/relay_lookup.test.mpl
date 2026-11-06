from Transparency.RelayLookup import RelayLookupPlan, prepare_relay_lookup
from Solana.Read import Pubkey, pubkey
from Solana.Tx import Instruction, AccountMeta

fn proof() -> Bool!String do
  let payer = pubkey("11111111111111111111111111111111")?
  let program = pubkey("5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb")?
  let keys = for index in 1..62 do
    Pubkey {
      bytes: Bytes.concat(Bytes.write_uint_le(Int.to_string(index), 1)?,
        Bytes.from_hex(String.repeat("00", 31))?)?
    }
  end
  let accounts = [AccountMeta { pubkey: payer, signer: true, writable: true }]
    ++ for key in keys do
      AccountMeta { pubkey: key, signer: false, writable: true }
    end
    ++ [
      AccountMeta { pubkey: List.head(keys), signer: false, writable: false },
      AccountMeta { pubkey: payer, signer: false, writable: false }
    ]
  let plan = prepare_relay_lookup(payer,
    Instruction { program_id: program, accounts: accounts, data: Bytes.empty() },
    U64.parse("9007199254740993")?)?
  assert(plan.addresses == keys)
  assert(List.length(plan.extend) == 4)
  let encoded = for instruction in plan.extend do
    assert(Bytes.length(instruction.data) <= 652)
    assert(Bytes.read_uint_le(instruction.data, 0, 4)? == "2")
    let count = U64.to_int(U64.parse(Bytes.read_uint_le(instruction.data, 4, 8)?)?)?
    assert(count >= 1 && count <= 20)
    for index in 0..count do
      Pubkey { bytes: Bytes.slice(instruction.data, 12 + index * 32, 32)? }
    end
  end
  assert(List.flat_map(encoded, fn(values) -> values end) == keys)
  assert(Bytes.read_uint_le(plan.create.data, 4, 8)? == "9007199254740993")
  assert(List.get(plan.close.accounts, 2).pubkey == payer)
  assert(Bytes.to_hex(plan.deactivate.data) == "03000000")
  assert(Bytes.to_hex(plan.close.data) == "04000000")
  Ok(true)
end

test("relay lookup plans retain exact settlement ordering, omit signers and bound each extension") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
