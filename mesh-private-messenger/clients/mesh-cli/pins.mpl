from Security.Config import SecurityConfig, security_config_parse, security_config_witness_keys
from Transparency.Merkle import WitnessKey

##! What this client trusts in the directory's evidence: the transparency
##! service key and the pinned witness set with its k, from the same security
##! config (v1 or v2) native builds pin. Without one, the version 1 variables
##! pin witness-a and witness-b, 2 of 2.

pub struct CliPins do
  service_key :: Bytes
  witnesses :: List<WitnessKey>
  threshold :: Int
  # The config's minimum suite for new sessions: 1 without a config.
  minimum_suite :: Int
  # The OHTTP gateway key configuration and relay the config pins, if any
  # (protocol/ohttp-v1.md): lookups, prekey claims and the mailbox go there.
  ohttp_key_config :: Bytes
  ohttp_relay :: String
end

fn pinned_key(name :: String, text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Ok(value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("#{name} must be a pinned 32-byte public key")
    end
    Err(_) -> Err("#{name} must be a pinned 32-byte public key")
  end
end

pub fn cli_pins(frame :: String,
  service_hex :: String,
  witness_a_hex :: String,
  witness_b_hex :: String) -> CliPins!String do
  if frame == "" do
    Ok(CliPins {
      service_key: pinned_key("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX", service_hex)?,
      witnesses: [
        WitnessKey {
          witness_id: "witness-a",
          public_key: pinned_key("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX", witness_a_hex)?
        },
        WitnessKey {
          witness_id: "witness-b",
          public_key: pinned_key("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX", witness_b_hex)?
        }
      ],
      threshold: 2,
      minimum_suite: 1,
      ohttp_key_config: Bytes.empty(),
      ohttp_relay: ""
    })
  else
    let config = security_config_parse(Bytes.from_utf8(frame))?
    Ok(CliPins {
      service_key: config.service_public_key,
      witnesses: security_config_witness_keys(config),
      threshold: config.threshold,
      minimum_suite: config.minimum_suite,
      ohttp_key_config: config.ohttp_key_config,
      ohttp_relay: config.ohttp_relay
    })
  end
end
