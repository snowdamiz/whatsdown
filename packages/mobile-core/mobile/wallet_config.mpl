from Mobile.Codec import mobile_byte, mobile_join, mobile_vector
from Mobile.Platform import native_security_config
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig

##! Mobile.WalletConfig: the Solana RPC URLs this build pins, for the in-app
##! wallet's balance reads and transfers (plan §6.13). The wallet reaches the
##! chain only through these; no wallet request goes to a Morse server.
##!
##! u8 1 || u8 count || count x vector32(url)   (count 0: no RPC is pinned)

pub fn wallet_rpc_urls(request :: Bytes) -> Bytes!String do
  if Bytes.length(request) > 0 do
    return Err("invalid_request")
  end
  let config = native_security_config()?
  let urls = config.config.rpc_urls
  let rows = for url in urls do
    mobile_vector(Bytes.from_utf8(url))?
  end
  mobile_join([mobile_byte(1)?, mobile_byte(List.length(urls))?] ++ rows, 0, Bytes.empty())
end
