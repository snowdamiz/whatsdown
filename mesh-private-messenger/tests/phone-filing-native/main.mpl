# Test-only embedding host. Production exports accept only the app database;
# this fixture seeds signed evidence and substitutes loopback transport origins.
from Mobile.ForkFiling import FilingPlan, prepare_filing, start_filing, filing_view
from Mobile.ForkFilingTransport import submit_filing
from Mobile.Platform import native_security_config
from Mobile.TransparencySafety import retain_fork, retained_fork
from Mobile.Codec import mobile_utf8
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_session
from Transparency.Config import SecurityConfig
from Transparency.Fork import ForkProof, ForkTarget, decode_fork
from Transparency.AnchorChain import AnchorPins
from Transparency.RpcTransport import webpki_rpc_transport, rpc_transport
from Transparency.SlashReceiptRead import read_slash_receipt_state
from MobileCore import fork_filing_export, transparency_fork_export, initialize

@export("phone_fixture_seed")
pub fn seed(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  ensure_schema(path)?
  let key = platform_key()?
  let wire = Bytes.from_hex(File.read(path <> ".wire")?)?
  let proof = decode_fork(wire)?
  case proof.second do
    SignedCheckpoint(_) -> retain_fork(path, key, proof)?
    AnchorReference(_) ->
      # The SBF fixture has already adjudicated this anchored proof. Seed the
      # retention boundary here; anchor discovery has its own protocol tests.
      let label = "transparency-fork/v1"
      store_updated_session(path, label, seal_local(wire, key, local_context(label)?)?)?
  end
  retained_fork(path, key)
end

@export("phone_fixture_start")
pub fn start(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let config = native_security_config()?
  let plan = case prepare_filing(config,
    webpki_rpc_transport(config.rpc_urls)?,
    retained_fork(path, key)?)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let ports = String.split(Env.get("MORSE_PHONE_FILING_PORTS", ""), ",")
  let origins = for port in ports do
    "http://127.0.0.1:" <> port
  end
  let local = webpki_rpc_transport(origins)?
  let pins = %{plan.pins | rpc: rpc_transport(local.sources, plan.pins.rpc.require_current)?}
  let state = start_filing(path,
    key,
    plan,
    U64.parse(File.read(path <> ".now")?)?,
    fn() do submit_filing(origins, plan.wire, plan.proof_hash) end,
    fn(floor :: U64) do read_slash_receipt_state(pins,
      config.service_public_key,
      config.log_version,
      plan.mint,
      plan.proof_hash,
      floor) end,
    fn() -> true end)?
  filing_view(plan, state)
end
