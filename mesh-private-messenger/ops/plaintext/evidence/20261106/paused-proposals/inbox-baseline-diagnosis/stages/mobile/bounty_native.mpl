from Mobile.Bounty import (
  BountyState,
  bounty_state,
  set_bounty_enabled,
  commit_bounty_address,
  abandon_bounty_address
)
from Mobile.Codec import mobile_utf8, mobile_byte, mobile_write_u64
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key

fn path(input :: Bytes) -> String!String do
  if Bytes.length(input) == 0 || Bytes.length(input) > 4096 do
    return Err("invalid_database_path")
  end
  mobile_utf8(input, "invalid_database_path")
end

fn output(state :: BountyState) -> Bytes!String do
  pack_credit_parts([
    Bytes.from_hex("01424650")?,
    mobile_byte(if state.enabled do
      1
    else
      0
    end)?,
    mobile_byte(state.status)?,
    state.proof_identity,
    state.finder,
    mobile_write_u64(state.index)?
  ])
end

fn parts(input :: Bytes, count :: Int) -> List<Bytes>!String do
  if Bytes.length(input) > 4250 do
    return Err("invalid_bounty_request")
  end
  let fields = unpack_credit_parts(input, count, 4096)?
  if List.length(fields) != count do
    return Err("invalid_bounty_request")
  end
  path(List.head(fields))?
  Ok(fields)
end

# This view is safe for generic JS. All authority-changing functions below are
# available only to trusted host orchestration, never generic invoke dispatch.
pub fn native_bounty_status(input :: Bytes) -> Bytes!String do
  let database = path(input)?
  ensure_schema(database)?
  let key = platform_key()?
  output(bounty_state(database, key)?)
end

# The host proves wallet presence using SDK op2 before enabling collection.
# Disabling needs no wallet. This preference cannot rewrite a retained proof.
pub fn native_bounty_set_enabled(input :: Bytes) -> Bytes!String do
  let fields = parts(input, 2)?
  let flag = List.get(fields, 1)
  if Bytes.length(flag) != 1 || Bytes.get(flag, 0)? > 1 do
    return Err("invalid_bounty_request")
  end
  let database = path(List.head(fields))?
  ensure_schema(database)?
  let key = platform_key()?
  output(set_bounty_enabled(database, key, Bytes.get(flag, 0)? == 1)?)
end

# The host passes its SDK result directly; neither index nor address comes
# from JS. SDK op4 has durably advanced its counter before returning these40B.
pub fn native_bounty_commit(input :: Bytes) -> Bytes!String do
  let fields = parts(input, 3)?
  let database = path(List.head(fields))?
  ensure_schema(database)?
  let key = platform_key()?
  output(commit_bounty_address(database, key, List.get(fields, 1), List.get(fields, 2))?)
end

# A failed local wallet operation cannot suppress the security evidence.
pub fn native_bounty_unavailable(input :: Bytes) -> Bytes!String do
  let fields = parts(input, 2)?
  let database = path(List.head(fields))?
  ensure_schema(database)?
  let key = platform_key()?
  output(abandon_bounty_address(database, key, List.get(fields, 1))?)
end
