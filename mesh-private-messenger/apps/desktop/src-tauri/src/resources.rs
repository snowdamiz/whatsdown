use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer};
use std::io::Read;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Config {
    pub security_frame: String,
    #[serde(default)]
    pub network_counter_frame: String,
    #[serde(default)]
    pub network_frame: String,
    #[serde(default)]
    pub ohttp_frame: String,
    #[serde(default)]
    pub credit_purpose: String,
    #[serde(default)]
    pub credit_usdc_mint_hex: String,
    #[serde(default)]
    pub lightning_network: String,
    #[serde(default)]
    pub issuer_tls_root: String,
    // Bundle schema: only a missing field maps to exactly [1, 0]. Present values must be
    // strings of canonical base64, at most 109,336 characters and 2..=82,002
    // decoded bytes. Invalid values remain Host errors, including JSON null.
    #[serde(default)]
    pub rpc_tls_roots: RpcTlsRoots,
    pub development: bool,
}

const MAX_FRAME: usize = 82_002;
const MAX_BASE64: usize = 109_336;

#[derive(Clone)]
pub(crate) struct RpcTlsRoots(Result<Vec<u8>, ()>);

impl Default for RpcTlsRoots {
    fn default() -> Self {
        Self(Ok(vec![1, 0]))
    }
}

impl<'de> Deserialize<'de> for RpcTlsRoots {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(encoded) => Self::read_present(encoded.as_bytes()),
            _ => Self(Err(())),
        })
    }
}

impl RpcTlsRoots {
    pub(crate) fn read_present(reader: impl Read) -> Self {
        let decode = || {
            let mut encoded = Vec::new();
            reader
                .take(MAX_BASE64 as u64 + 1)
                .read_to_end(&mut encoded)
                .map_err(|_| ())?;
            if encoded.is_empty() || encoded.len() > MAX_BASE64 {
                return Err(());
            }
            let bytes = STANDARD.decode(&encoded).map_err(|_| ())?;
            if !(2..=MAX_FRAME).contains(&bytes.len())
                || STANDARD.encode(&bytes).as_bytes() != encoded
            {
                return Err(());
            }
            Ok(bytes)
        };
        Self(decode())
    }

    pub(crate) fn bytes(&self) -> Result<&[u8], i32> {
        self.0.as_deref().map_err(|_| 3)
    }
}
