from Mobile.Codec import encode_output_list
from Mobile.Platform import native_security_config
from Mobile.Codec import current_time, mobile_wide
from Privacy.Edge import mint_request_stamp, encode_stamped_request
from Mobile.Transparency import transparency_checkpoint_bytes, transparency_lookup_for_config
from Mobile.Types import MobilePayloadRequest
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Transparency.Config import SecurityConfig
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint

# Mesh selects the permitted profiles from native pins and durable history.
# The host may try the second request only when the RFC endpoint explicitly
# reports that cutover has not activated; a failed proof never permits fallback.
pub struct DirectoryResolutionRequest do
  version :: Int
  path :: String
  body :: Bytes
end

pub fn resolution_requests(request :: MobilePayloadRequest) -> List<DirectoryResolutionRequest>!String do
  ensure_schema(request.database_path)?
  let config = native_security_config()?
  let previous = transparency_checkpoint_bytes(request.database_path, platform_key()?)?
  resolution_requests_for_config(request, config, previous)
end

# Supplied native frames/checkpoint are retained through plan selection and stamp.
pub fn resolution_requests_for_config(request :: MobilePayloadRequest,
  config :: SecurityConfig,
  previous :: Bytes) -> List<DirectoryResolutionRequest>!String do
  let previous_version = if Bytes.length(previous) == 0 do
    0
  else
    decode_checkpoint(previous)?.version
  end
  let versions = if (config.version == 3 || config.version == 4 || config.version == 5)
    && previous_version != 2 do
    [2, 1]
  else
    [config.log_version]
  end
  let plans = for version in versions do
    let lookup = transparency_lookup_for_config(request, version, config, previous)?
    let body = encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/resolve",
        lookup,
        U64.add(current_time()?, mobile_wide("240000")?)?,
        config.abuse_difficulty)?,
      lookup)?
    let path = if version == 2 do
      "/v2/devices/resolve"
    else
      "/v1/devices/resolve"
    end
    DirectoryResolutionRequest { version: version, path: path, body: body }
  end
  Ok(plans)
end

pub fn resolution_plan(request :: MobilePayloadRequest) -> Bytes!String do
  let steps = resolution_requests(request)?
  let plans = for step in steps do
    encode_output_list([Bytes.from_utf8(step.path), step.body])?
  end
  encode_output_list(plans)
end
