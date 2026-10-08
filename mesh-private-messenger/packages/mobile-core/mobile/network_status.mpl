from Mobile.Anchor import AnchorRecord, anchor_record_load
from Mobile.Codec import (
  mobile_byte,
  mobile_join,
  mobile_vector,
  mobile_wide,
  mobile_write_u16,
  mobile_write_u64
)
from Mobile.GroupSets import group_update_required
from Mobile.Platform import native_security_config
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig, SecurityWitness, security_config_morse_run
from Storage.Blobs import ensure_schema
from Mobile.TrustAlarm import TrustAlarm, trust_alarm_active
from Storage.Keys import platform_key

##! Mobile.NetworkStatus: what Settings -> Network and the safety number screen
##! show about the witness network, computed on this device.
##!
##! u8 1 || "NST" || vector32(profile: bootstrap | transitional | open)
##!   || u8 k || u8 n || u8 m (Morse-run) || set_id32
##!   || n x (vector32(witness_id) || vector32(label) || u8 morse_run)
##!   || u8 sections || sections x (u16 tag || vector32(body))
##!
##! Sections carry state beyond the config; readers skip tags they do not
##! know. Tag 1 (body u8 1): a group this device is in uses a witness set this
##! build does not know, so the person should update Morse. Tags 2-4 hold the
##! phone's last check against the public record, the bond counter and the
##! blocking trust alarm (below).

fn witness_row(id :: String, label :: String) -> Bytes!String do
  mobile_join([
      mobile_vector(Bytes.from_utf8(id))?,
      mobile_vector(Bytes.from_utf8(label))?,
      mobile_byte(if label == "Morse" do
        1
      else
        0
      end)?
    ],
    0,
    Bytes.empty())
end

fn section(tag :: Int, body :: Bytes) -> Bytes!String do
  mobile_join([mobile_write_u16(tag)?, mobile_vector(body)?], 0, Bytes.empty())
end

# Tag 2: the phone's last anchor check (Mobile.Anchor): u8 outcome ||
# u64 checked_at_ms || u64 last public checkpoint time (ms, 0 unknown) ||
# u64 its slot || u64 its tree size; outcome 0 when never checked.
# Tag 3: the bond counter (Mobile.BondCounter), once one was read.
# Tag 4: the blocking trust alarm (Mobile.TrustAlarm): u8 kind ||
# u64 raised_at_ms.

fn u64(value :: Int) -> Bytes!String do
  mobile_write_u64(mobile_wide(Int.to_string(value))?)
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(parts, 0, Bytes.empty())
end

# Sections 2-4 appear once the build pins an anchor or relays, or a check has
# run; a build without them (security config v1) shows none.

fn anchor_sections(database_path :: String, config :: MobileSecurityConfig) -> List<Bytes>!String do
  let record = anchor_record_load(database_path)?
  let pinned = config.config.log_account != "" || List.length(config.config.relays) > 0
  let recorded = case record do
    Some(_) -> true
    None -> false
  end
  if !pinned && !recorded do
    return Ok(List.new())
  end
  let check = case record do
    None -> section(2, join([mobile_byte(0)?, u64(0)?, u64(0)?, u64(0)?, u64(0)?])?)?
    Some(value) -> section(2,
      join([
        mobile_byte(value.outcome)?,
        u64(value.checked_at)?,
        u64(value.anchor_ms)?,
        u64(value.anchor_slot)?,
        u64(value.public_size)?
      ])?)?
  end
  let bonds = case record do
    Some(value) -> if Bytes.length(value.bonds) > 0 do
      [section(3, value.bonds)?]
    else
      List.new()
    end
    None -> List.new()
  end
  let alarm = case trust_alarm_active(database_path)? do
    None -> List.new()
    Some(value) -> [section(4, join([mobile_byte(value.kind)?, u64(value.raised_at)?])?)?]
  end
  Ok([check] ++ bonds ++ alarm)
end

pub fn network_status(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    return Err("invalid_database_path")
  end
  ensure_schema(database_path)?
  let config = native_security_config()?
  let witnesses = config.config.witnesses
  let rows = for witness in witnesses do
    witness_row(witness.witness_id, witness.label)?
  end
  let update = if group_update_required(database_path, platform_key()?, config)? do
    [section(1, mobile_byte(1)?)?]
  else
    List.new()
  end
  let sections = update ++ anchor_sections(database_path, config)?
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("NST"),
      mobile_vector(Bytes.from_utf8(config.profile))?,
      mobile_byte(config.config.threshold)?,
      mobile_byte(List.length(witnesses))?,
      mobile_byte(security_config_morse_run(config.config))?,
      config.config.set_id
    ]
      ++ rows
      ++ [mobile_byte(List.length(sections))?]
      ++ sections,
    0,
    Bytes.empty())
end
