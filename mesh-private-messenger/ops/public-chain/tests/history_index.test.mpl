from HistoryIndex import (
  PublicHistoryScope,
  PublicHistoryAccount,
  PublicHistorySnapshot,
  decode_public_history
)
from Solana.Read import Pubkey, AccountInfo, pubkey
from Solana.Address import find_program_address

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn actual(requested_kind :: Int) -> (PublicHistoryScope, PublicHistorySnapshot)!String do
  let kind = if requested_kind == 3 do
    2
  else
    requested_kind
  end
  let path = if requested_kind == 3 do
    Env.get("MORSE_PUBLIC_HISTORY_LEGACY_FIXTURE", "")
  else if kind == 0 do
    Env.get("MORSE_PUBLIC_HISTORY_TOKEN_FIXTURE", "")
  else
    Env.get("MORSE_PUBLIC_HISTORY_JUDGE_FIXTURE", "")
  end
  if path == "" do
    return Err("actual_complete_sbf_fixture_required")
  end
  let root = Json.parse(File.read(path)?)?
  let owned = Json.array_get(Json.object_get(root, "owned")?, 0)?
  let program = pubkey(text(owned, "program")?)?
  let metadata = Json.object_get(root, "metadata")?
  let scope = if kind == 0 do
    PublicHistoryScope {
      kind: kind,
      program: program,
      binding: find_program_address(program, [Bytes.from_utf8("swap")])?.address.bytes,
      usdc: pubkey(text(metadata, "usdc")?)?.bytes,
      morse: find_program_address(program, [Bytes.from_utf8("mint")])?.address.bytes,
      treasury: pubkey(text(metadata, "treasury")?)?.bytes
    }
  else
    let roles = Json.object_get(metadata, "accounts")?
    PublicHistoryScope {
      kind: kind,
      program: program,
      binding: Bytes.from_hex(text(metadata, "log_id")?)?,
      usdc: if requested_kind == 3 do
        pubkey(text(metadata, "mint")?)?.bytes
      else
        pubkey(text(Json.object_get(roles, "usdc")?, "address")?)?.bytes
      end,
      morse: if requested_kind == 3 do # Explicit public pin required by shared scope; MPRv1 does not authenticate it.
        let current = Json.parse(File.read(Env.get("MORSE_PUBLIC_HISTORY_JUDGE_FIXTURE", ""))?)?
        let known = Json.object_get(Json.object_get(Json.object_get(current, "metadata")?,
            "accounts")?,
          "morse")?
        pubkey(text(known, "address")?)?.bytes
      else
        pubkey(text(Json.object_get(roles, "morse")?, "address")?)?.bytes
      end,
      treasury: Bytes.empty()
    }
  end
  let rows = Json.object_get(owned, "accounts")?
  let all = for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    PublicHistoryAccount {
      address: pubkey(text(row, "address")?)?,
      account: AccountInfo {
        data: Bytes.from_hex(text(row, "data_hex")?)?,
        owner: pubkey(text(row, "owner")?)?,
        executable: Json.as_bool(Json.object_get(row, "executable")?)?,
        lamports: U64.parse(text(row, "lamports")?)?,
        rent_epoch: U64.parse(text(row, "rent_epoch")?)?
      },
      space: U64.parse(text(row, "space")?)?
    }
  end
  let selected = for row in all do
    let data = row.account.data
    let matching = if kind == 0 do
      Bytes.length(data) >= 36
        && Bytes.slice(data, 0, 2)? == Bytes.from_utf8("MT")
        && Bytes.slice(data, 4, 32)? == scope.binding
    else if kind == 1 do
      Bytes.length(data) >= 232
        && Bytes.slice(data, 0, 3)? == Bytes.from_utf8("MWI")
        && Bytes.slice(data, 200, 32)? == scope.binding
    else
      Bytes.length(data) >= 40
        && Bytes.slice(data, 0, 3)? == Bytes.from_utf8("MPR")
        && Bytes.slice(data, 8, 32)? == scope.binding
    end
    if matching do
      Some(row)
    else
      None
    end
  end
  let accounts = List.flat_map(selected,
    fn(value) do
      case value do
        None -> []
        Some(account) -> [account]
      end
    end)
  Ok((scope,
    PublicHistorySnapshot { slot: U64.parse(text(root, "context_slot")?)?, accounts: accounts }))
end

fn complete() -> Bool!String do
  for kind in 0..3 do
    let (scope, snapshot) = actual(kind)?
    assert(List.length(snapshot.accounts) == List.get([4, 65, 1], kind))
    let value = decode_public_history(scope, snapshot, snapshot.slot, 128)?
    assert(List.length(value.records) == List.length(snapshot.accounts))
    assert(value.slot == snapshot.slot)
    assert(value.supported_layouts_complete)
  end
  Ok(true)
end

test("complete actual SBF enumerations retain all funded versions and every registered identity/proof") do
  case complete() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn change(data :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(data, 0, at)?, value)?,
    Bytes.slice(data, at + Bytes.length(value), Bytes.length(data) - at - Bytes.length(value))?)
end

fn replace_first(snapshot :: PublicHistorySnapshot,
  value :: PublicHistoryAccount) -> PublicHistorySnapshot do
  %{snapshot |
    accounts: for index in 0..List.length(snapshot.accounts) do
      if index == 0 do
        value
      else
        List.get(snapshot.accounts, index)
      end
    end
  }
end

fn refusals() -> Bool!String do
  for kind in 0..3 do
    let (scope, snapshot) = actual(kind)?
    let first = List.get(snapshot.accounts, 0)
    let original = decode_public_history(scope, snapshot, snapshot.slot, 128)?
    let reversed = decode_public_history(scope,
      %{snapshot | accounts: List.reverse(snapshot.accounts)},
      snapshot.slot,
      128)?
    assert(original.records == reversed.records && original.digest == reversed.digest)
    let later = decode_public_history(scope,
      %{snapshot | slot: U64.add(snapshot.slot, U64.parse("1")?)?},
      snapshot.slot,
      128)?
    assert(later.digest != original.digest)
    assert(Result.is_err(decode_public_history(scope,
      snapshot,
      U64.add(snapshot.slot, U64.parse("1")?)?,
      128)))
    assert(Result.is_err(decode_public_history(scope, snapshot, snapshot.slot, 0)))
    assert(Result.is_err(decode_public_history(scope, snapshot, snapshot.slot, 129)))
    assert(Result.is_err(decode_public_history(scope,
      %{snapshot | accounts: List.append(snapshot.accounts, first)},
      snapshot.slot,
      128)))
    for bad in [
      %{first | address: scope.program},
      %{first | space: U64.add(first.space, U64.parse("1")?)?},
      %{first | account: %{first.account | owner: Pubkey { bytes: scope.usdc }}},
      %{first | account: %{first.account | executable: true}},
      %{first | account: %{first.account | lamports: U64.parse("0")?}},
      %{first |
        account: %{first.account | data: change(first.account.data, 0, Bytes.from_utf8("BAD"))?}
      },
      %{first |
        space: U64.add(first.space, U64.parse("1")?)?,
        account: %{first.account | data: Bytes.concat(first.account.data, Bytes.from_hex("00")?)?}
      }
    ] do
      assert(Result.is_err(decode_public_history(scope,
        replace_first(snapshot, bad),
        snapshot.slot,
        128)))
    end
  end
  let (scope, snapshot) = actual(1)?
  assert(List.length(snapshot.accounts) == 65)
  assert(Result.is_err(decode_public_history(scope, snapshot, snapshot.slot, 64)))
  Ok(true)
end

fn unsupported() -> Bool!String do
  for kind in 0..3 do
    let (scope, snapshot) = actual(kind)?
    let first = List.get(snapshot.accounts, 0)
    let future = %{first |
      account: %{first.account | data: change(first.account.data, 3, Bytes.from_hex("63")?)?}
    }
    let observed = decode_public_history(scope,
      replace_first(snapshot, future),
      snapshot.slot,
      128)?
    assert(!observed.supported_layouts_complete)
    let row = List.head(List.filter(observed.records,
      fn(value) do value.address == first.address end))
    assert(row.verification == "unsupported-layout" && row.version == 99)
    assert(row.epoch == None
      && row.witness_id == ""
      && Bytes.length(row.public_key) == 0
      && Bytes.length(row.proof_hash) == 0)
    let wrong = %{future | account: %{future.account | owner: Pubkey { bytes: scope.usdc }}}
    assert(Result.is_err(decode_public_history(scope,
      replace_first(snapshot, wrong),
      snapshot.slot,
      128)))
    # An unknown-layout address is retained only as an unvalidated observation.
    # It cannot acquire a canonical known identity or join a value page.
    let other = decode_public_history(scope,
      replace_first(snapshot, %{future | address: scope.program}),
      snapshot.slot,
      128)?
    let unknown = List.head(List.filter(other.records,
      fn(value) do value.address == scope.program end))
    assert(!other.supported_layouts_complete && unknown.verification == "unsupported-layout")
    assert(unknown.epoch == None
      && unknown.witness_id == ""
      && Bytes.length(unknown.proof_hash) == 0)
  end
  Ok(true)
end

test("ordering is irrelevant but duplicate count context owner PDA filter funding executable and trailing bytes refuse") do
  case refusals() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("unsupported layouts remain explicit unvalidated observations without canonical identity or custody authority") do
  case unsupported() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn legacy() -> Bool!String do
  let (scope, snapshot) = actual(3)?
  assert(List.length(snapshot.accounts) == 1)
  let value = decode_public_history(scope, snapshot, snapshot.slot, 128)?
  let row = List.head(value.records)
  assert(row.version == 1 && row.verification == "legacy")
  assert(Bytes.length(row.proof_hash) == 32 && row.epoch == None)
  assert(row.witness_id == "" && Bytes.length(row.public_key) == 0)
  let first = List.head(snapshot.accounts)
  assert(Result.is_err(decode_public_history(scope,
    %{snapshot | accounts: [%{first | address: scope.program}]},
    snapshot.slot,
    128)))
  assert(Result.is_err(decode_public_history(%{scope | usdc: scope.program.bytes},
    snapshot,
    snapshot.slot,
    128)))
  let trailing = Bytes.concat(first.account.data, Bytes.from_hex("00")?)?
  assert(Result.is_err(decode_public_history(scope,
    %{snapshot |
      accounts: [%{first | space: U64.parse("385")?, account: %{first.account | data: trailing}}]
    },
    snapshot.slot,
    128)))
  Ok(true)
end

test("genuine legacy MPRv1 bank retains only a canonical proof identifier without v2 custody or full-context claims") do
  case legacy() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
