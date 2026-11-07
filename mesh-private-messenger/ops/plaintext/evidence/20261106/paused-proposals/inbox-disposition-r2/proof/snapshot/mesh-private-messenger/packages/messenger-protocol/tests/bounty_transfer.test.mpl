from Bounty.Transfer import (
  BountyTransfer,
  encode_bounty_transfer,
  decode_bounty_transfer,
  validate_bounty_transfer,
  bounty_transfer_instructions,
  authenticate_bounty_transfer
)
from Bounty.Settlement import bounty_transfer_settlement
from Bounty.Transfer import bounty_token_account
from Solana.Read import Pubkey, Hash, Signature, pubkey, spl_token_program
from Solana.Tx import Instruction, AccountMeta, compile_legacy_message, serialize_legacy_message
from Solana.TransactionRead import (
  FinalizedTransaction,
  FinalizedTransactionOutcome,
  TransactionTokenBalance
)
from Solana.TransactionWrite import serialize_signed_legacy_transaction

fn bytes(value :: Int) -> Bytes!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("test bytes")
    Ok(result)
  end
end

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let payer = pair()?
  let finder = pair()?
  let usdc = bytes(9)?
  let intent = BountyTransfer {
    index: U64.parse("2147483647")?,
    finder: finder.public_key.bytes,
    destination: bytes(7)?,
    mint: usdc,
    amount: U64.parse("18446744073709551614")?,
    blockhash: bytes(8)?,
    issued_at: U64.parse("1000")?,
    expires_at: U64.parse("1300")?,
    purpose: 1,
    decimals: 6
  }
  let encoded = encode_bounty_transfer(intent)?
  assert(Bytes.length(encoded) == 166)
  assert(Bytes.to_hex(Bytes.slice(encoded, 0, 12)?) == "01425754000000007fffffff")
  assert(Bytes.secure_equals(encode_bounty_transfer(decode_bounty_transfer(encoded)?)?, encoded))
  validate_bounty_transfer(intent, usdc, 1, U64.parse("1000")?)?
  validate_bounty_transfer(intent, usdc, 1, U64.parse("1299")?)?
  assert(Result.is_err(validate_bounty_transfer(intent, usdc, 0, intent.issued_at)))
  assert(Result.is_err(validate_bounty_transfer(intent, usdc, 1, U64.parse("999")?)))
  assert(Result.is_err(validate_bounty_transfer(intent, usdc, 1, intent.expires_at)))
  for invalid in [
    %{intent | index: U64.parse("2147483648")?},
    %{intent | amount: U64.parse("0")?},
    %{intent | finder: bytes(0)?},
    %{intent | destination: intent.finder},
    %{intent | blockhash: bytes(0)?},
    %{intent | expires_at: U64.parse("1301")?},
    %{intent | purpose: 2},
    %{intent | decimals: 19}
  ] do
    assert(Result.is_err(encode_bounty_transfer(invalid)))
  end
  assert(Result.is_err(validate_bounty_transfer(%{intent | decimals: 5},
    usdc,
    1,
    intent.issued_at)))
  assert(Result.is_err(decode_bounty_transfer(Bytes.slice(encoded, 0, 165)?)))
  assert(Result.is_err(decode_bounty_transfer(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  let payer_key = Pubkey { bytes: payer.public_key.bytes }
  # Own payment wallet and an external owner are both valid destinations.
  for destination in [intent.destination, payer.public_key.bytes] do
    let current = %{intent | destination: destination}
    let expected = bounty_transfer_instructions(current, payer_key)?
    let normal = List.get(expected, 1)
    let corrupted = Bytes.concat(Bytes.from_hex("0c0100000000000000")?, Bytes.from_hex("06")?)?
    let variants = [
      expected,
      [%{List.head(expected) | data: Bytes.from_hex("00")?}, normal],
      [List.head(expected), %{normal | data: corrupted}],
      [List.head(expected), %{normal | program_id: pubkey("11111111111111111111111111111111")?}],
      expected
        ++ [Instruction { program_id: normal.program_id, accounts: [], data: Bytes.empty() }],
      [
        List.head(expected),
        %{normal |
          accounts: normal.accounts
            ++ [
              AccountMeta { pubkey: Pubkey { bytes: bytes(11)? }, signer: false, writable: false }
            ]
        }
      ]
    ]
    for index in 0..List.length(variants) do
      let message = compile_legacy_message(payer_key,
        Hash { bytes: current.blockhash },
        List.get(variants, index))?
      let body = serialize_legacy_message(message)?
      let first = case Crypto.sign(payer.private_key, body) do
        Err(_) -> return Err("test sign")
        Ok(value) -> value
      end
      let second = case Crypto.sign(finder.private_key, body) do
        Err(_) -> return Err("test sign")
        Ok(value) -> value
      end
      let packet = serialize_signed_legacy_transaction(message, [first, second])?
      let checked = authenticate_bounty_transfer(packet, current, payer_key, usdc, 1)
      if index == 0 do
        assert(Bytes.secure_equals(checked?.signature, first.bytes))
        let signed = checked?
        let source = bounty_token_account(current.finder, current.mint)?
        let destination = bounty_token_account(current.destination, current.mint)?
        let source_index = List.head(List.filter(for position in 0..List.length(signed.accounts) do
            position
          end,
          fn(position) do Bytes.secure_equals(List.get(signed.accounts, position).pubkey.bytes,
            source.bytes) end))
        let destination_index = List.head(List.filter(for position in 0..List.length(signed.accounts) do
            position
          end,
          fn(position) do Bytes.secure_equals(List.get(signed.accounts, position).pubkey.bytes,
            destination.bytes) end))
        let source_before = TransactionTokenBalance {
          account_index: source_index,
          mint: Pubkey { bytes: current.mint },
          owner: Some(Pubkey { bytes: current.finder }),
          program_id: Some(spl_token_program()?),
          amount: U64.parse("18446744073709551615")?,
          decimals: 6
        }
        let source_after = %{source_before | amount: U64.parse("1")?}
        let destination_after = %{source_before |
          account_index: destination_index,
          owner: Some(Pubkey { bytes: current.destination }),
          amount: current.amount
        }
        let outcome = FinalizedTransactionOutcome {
          execution_error: None,
          transaction: FinalizedTransaction {
            signed: signed,
            slot: U64.parse("91")?,
            block_time: None,
            fee: U64.parse("10000")?,
            pre_balances: for _account in signed.accounts do
              U64.parse("10000")?
            end,
            post_balances: for _account in signed.accounts do
              U64.parse("10000")?
            end,
            pre_token_balances: [source_before],
            post_token_balances: [source_after, destination_after],
            inner_instruction_count: 0,
            inner_instructions: []
          }
        }
        assert(bounty_transfer_settlement(outcome,
          packet,
          current,
          payer_key,
          usdc,
          1,
          U64.parse("90")?)?.execution_error == "")
        assert(Result.is_err(bounty_transfer_settlement(outcome,
          packet,
          current,
          payer_key,
          usdc,
          1,
          U64.parse("92")?)))
        for changed in [
          [source_after, %{destination_after | amount: U64.parse("5")?}],
          [%{source_after | amount: U64.parse("2")?}, destination_after],
          [source_after, %{destination_after | owner: None}],
          [source_after, destination_after, destination_after]
        ] do
          assert(Result.is_err(bounty_transfer_settlement(%{outcome |
              transaction: %{outcome.transaction | post_token_balances: changed}
            },
            packet,
            current,
            payer_key,
            usdc,
            1,
            U64.parse("90")?)))
        end
        assert(bounty_transfer_settlement(%{outcome |
            execution_error: Some("\"InsufficientFundsForFee\"")
          },
          packet,
          current,
          payer_key,
          usdc,
          1,
          U64.parse("90")?)?.execution_error != "")
        assert(Result.is_err(authenticate_bounty_transfer(packet,
          %{current | destination: bytes(12)?},
          payer_key,
          usdc,
          1)))
        assert(Result.is_err(authenticate_bounty_transfer(packet,
          %{current | blockhash: bytes(12)?},
          payer_key,
          usdc,
          1)))
        assert(Result.is_err(authenticate_bounty_transfer(packet,
          current,
          Pubkey { bytes: bytes(12)? },
          usdc,
          1)))
      else
        assert(Result.is_err(checked))
      end
    end
  end
  for address in [
    intent.finder,
    intent.mint,
    pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?.bytes
  ] do
    assert(Result.is_err(bounty_transfer_instructions(%{intent | destination: address}, payer_key)))
  end
  Ok(true)
end

test("bounty transfer validates exact two-signer SPL intent, expiry, aliases and u64 amounts") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
