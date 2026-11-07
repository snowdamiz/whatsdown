from MobileCore import initialize
from Mobile.Bounty import bounty_state, set_bounty_enabled, commit_bounty_address, disclosable_fork
from Mobile.TransparencySafety import retain_fork
from Mobile.Codec import mobile_utf8, encode_output_list
from Mobile.BountyTransferState import read_bounty_transfer_route
from Mobile.CreditState import unpack_credit_parts
from Transparency.Fork import decode_fork
from Storage.Keys import platform_key, open_local, local_context
from Bounty.Transfer import decode_bounty_transfer
from Mobile.BountyTransferNetwork import submit_bounty_journal
from Mobile.OhttpContext import capture_native_ohttp_context, rpc_transport_from_context
from Storage.Blobs import load_blob
from Storage.BountyTransfer import bounty_transfer_row_label

@export("bounty_fixture_seed_selected")
pub fn seed_selected(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let wire = Bytes.from_hex(File.read(path <> ".wire")?)?
  let proof = decode_fork(wire)?
  set_bounty_enabled(path, key, true)?
  retain_fork(path, key, proof)?
  let state = bounty_state(path, key)?
  commit_bounty_address(path,
    key,
    state.proof_identity,
    Bytes.concat(Bytes.from_hex("0300000000000000")?, proof.finder)?)?
  disclosable_fork(path, key)
end

@export("bounty_fixture_history")
pub fn history(request :: Bytes) -> Bytes!String do
  let parts = unpack_credit_parts(request, 3, 4096)?
  let path = mobile_utf8(List.head(parts), "invalid_path")?
  let asset = Bytes.get(List.get(parts, 1), 0)?
  let key = platform_key()?
  let route = read_bounty_transfer_route(path, key, asset)?
  let label = bounty_transfer_row_label(Bytes.to_hex(route.root.claim_id), asset)? <> "/history/" <> Bytes.to_hex(List.get(parts, 2))
  let ciphertext = load_blob(path, label)?
  encode_output_list([ciphertext, open_local(ciphertext, key, local_context(label)?)?])
end

@export("bounty_fixture_submit_time")
pub fn submit_time(request :: Bytes) -> Bytes!String do
  let parts = unpack_credit_parts(request, 3, 4096)?
  let path = mobile_utf8(List.head(parts), "invalid_path")?
  let asset = Bytes.get(List.get(parts, 1), 0)?
  let key = platform_key()?
  let context = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
  let rpc = rpc_transport_from_context(path, context)?
  let value = case read_bounty_transfer_route(path, key, asset)?.journal do
    None -> return Err("fixture_journal_missing")
    Some(value) -> value
  end
  let result = submit_bounty_journal(path, key, rpc, value,
    U64.parse(mobile_utf8(List.get(parts, 2), "invalid_clock")?)?, fn() -> true end)?
  Ok(Bytes.from_utf8(Int.to_string(result.status)))
end


@export("bounty_fixture_journal")
pub fn journal(request :: Bytes) -> Bytes!String do
  let parts = unpack_credit_parts(request, 2, 4096)?
  let path = mobile_utf8(List.head(parts), "invalid_path")?
  let asset = Bytes.get(List.get(parts, 1), 0)?
  let key = platform_key()?
  let route = read_bounty_transfer_route(path, key, asset)?
  case route.journal do
    None -> encode_output_list([Bytes.from_utf8("ready"), route.identity])
    Some(value) -> encode_output_list([
      Bytes.from_utf8(Int.to_string(value.status)),
      value.identity,
      value.intent,
      value.wire,
      value.signature,
      Bytes.from_utf8(U64.to_string(value.fee)),
      Bytes.from_utf8(U64.to_string(value.context_slot)),
      Bytes.from_utf8(U64.to_string(value.finalized_slot)),
      Bytes.from_utf8(value.execution_error)
    ])
  end
end
