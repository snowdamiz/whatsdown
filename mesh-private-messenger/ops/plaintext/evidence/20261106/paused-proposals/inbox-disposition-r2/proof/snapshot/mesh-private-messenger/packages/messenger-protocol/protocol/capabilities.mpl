##! Advertised device features. Callers authenticate the enclosing credential
##! and its current witnessed device set before relying on a capability.

# Bit1 is the existing baseline; bit2 (mask2) advertises ACH3 bound chunks.
# Inspect the low byte without coercing an unsigned capability mask to Int.
pub fn supports_ach3(capabilities :: U64) -> Bool do
  case Bytes.write_u64_be(capabilities) do
    Err(_) -> false
    Ok(encoded) -> case Bytes.get(encoded, 7) do
      Err(_) -> false
      Ok(value) -> value % 4 >= 2
    end
  end
end

# Mask4 advertises fixed-size EAM4/ACH4 reads. It is meaningful only inside
# the same authenticated credential/device-set boundary as existing claims.
pub fn supports_attachment_buckets(capabilities :: U64) -> Bool do
  case Bytes.write_u64_be(capabilities) do
    Err(_) -> false
    Ok(encoded) -> case Bytes.get(encoded, 7) do
      Err(_) -> false
      Ok(value) -> value % 8 >= 4
    end
  end
end

# Mask8 advertises the version2 HE handshake and version4 encrypted ratchet header.
pub fn supports_header_encryption(capabilities :: U64) -> Bool do
  case Bytes.write_u64_be(capabilities) do
    Err(_) -> false
    Ok(encoded) -> case Bytes.get(encoded, 7) do
      Err(_) -> false
      Ok(value) -> value % 16 >= 8
    end
  end
end

# Mask16 authenticates GMS6/GAP2 disappearing group-message reads.
pub fn supports_group_expiry(capabilities :: U64) -> Bool do
  case Bytes.write_u64_be(capabilities) do
    Err(_) -> false
    Ok(encoded) -> case Bytes.get(encoded, 7) do
      Err(_) -> false
      Ok(value) -> value % 32 >= 16
    end
  end
end
