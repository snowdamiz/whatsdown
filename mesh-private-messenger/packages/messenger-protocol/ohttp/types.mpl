##! Bounded Binary HTTP values. These types confer no gateway routing authority.

pub type BhttpError do
  BhttpInvalidLimits
  BhttpInputTooLarge
  BhttpUnexpectedEnd
  BhttpInvalidFraming
  BhttpInvalidStatus
  BhttpInvalidControl
  BhttpInvalidField
  BhttpInvalidPadding
  BhttpLimitExceeded
  BhttpOutputTooLarge
end deriving(Eq, Debug)

pub type BhttpFraming do
  BhttpKnownLength
  BhttpIndeterminateLength
end

pub struct BhttpLimits do
  wire_bytes :: Int
  content_bytes :: Int
  field_bytes :: Int
  field_count :: Int
  control_bytes :: Int
  informational_count :: Int
  content_chunks :: Int
end

# Field counts and name/value bytes are aggregate across all informational,
# final-header and trailer sections, not a separate allowance for every block.
pub fn default_bhttp_limits() -> BhttpLimits do
  BhttpLimits {
    wire_bytes: 1048576,
    content_bytes: 1048576,
    field_bytes: 8192,
    field_count: 16,
    control_bytes: 4096,
    informational_count: 4,
    content_chunks: 1024
  }
end

pub struct BhttpField do
  name :: Bytes
  value :: Bytes
end

pub struct BhttpInformational do
  status :: Int
  fields :: List<BhttpField>
end

pub struct BhttpRequest do
  method :: Bytes
  scheme :: Bytes
  authority :: Bytes
  path :: Bytes
  fields :: List<BhttpField>
  content :: Bytes
  trailers :: List<BhttpField>
end

pub struct BhttpResponse do
  informational :: List<BhttpInformational>
  status :: Int
  fields :: List<BhttpField>
  content :: Bytes
  trailers :: List<BhttpField>
end
