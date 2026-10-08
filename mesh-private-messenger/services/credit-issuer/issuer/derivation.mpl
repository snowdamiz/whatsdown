##! Deposit keys: SLIP-0010 Ed25519 derivation (hardened only), the same
##! derivation packages/wallet-core uses, over the treasury deposit seed.
##!
##! - quote q pays to `m/44'/501'/q'/0'` (q < 2,147,483,645), the account path
##!   every Solana wallet derives, so the seed can be restored anywhere;
##! - sweeps and refunds pay fees from `m/44'/501'/2147483645'/0'` (the fee
##!   payer, funded by the operator), just below wallet-core's bounty branch.
##!
##! Mesh has no secret HMAC-SHA-512, so this computes it over `Bytes` from
##! `Crypto.sha512`: the seed and deposit keys are ordinary (not zeroized)
##! memory in this process. They only control deposits, which are swept to a
##! treasury whose key never reaches the server.

pub struct DepositKey do
  index :: Int
  secret :: Bytes
  public_key :: Bytes
  address :: String
end

pub fn issuer_fee_payer_index() -> Int do
  2147483645
end

fn power(exponent :: Int) -> Int do
  if exponent <= 0 do
    1
  else
    2 * power(exponent - 1)
  end
end

fn xor_bits(left :: Int, right :: Int, bit :: Int, output :: Int) -> Int do
  if bit >= 8 do
    output
  else
    let place = power(bit)
    let differs = left / place % 2 != right / place % 2
    xor_bits(left,
      right,
      bit + 1,
      output
        + if differs do
          place
        else
          0
        end)
  end
end

fn padded(key :: Bytes, pad :: Int) -> Bytes!String do
  let block = if Bytes.length(key) > 128 do
    Crypto.sha512(key)
  else
    key
  end
  let bytes = Bytes.to_list(block)
  let values = for index in 0..128 do
    xor_bits(if index < List.length(bytes) do
        List.get(bytes, index)
      else
        0
      end,
      pad,
      0,
      0)
  end
  case Bytes.from_list(values) do
    Err(_) -> Err("hmac padding failed")
    Ok(output)
  end
end

fn joined(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("derivation allocation failed")
    Ok(output)
  end
end

## HMAC-SHA-512 (RFC 2104) over ordinary bytes.

pub fn issuer_hmac_sha512(key :: Bytes, message :: Bytes) -> Bytes!String do
  let inner = Crypto.sha512(joined(padded(key, 54)?, message)?)
  Ok(Crypto.sha512(joined(padded(key, 92)?, inner)?))
end

fn part(value :: Bytes, start :: Int) -> Bytes!String do
  case Bytes.slice(value, start, 32) do
    Err(_) -> Err("derivation slice failed")
    Ok(output)
  end
end

fn hardened(index :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(index + 2147483648))?) do
    Err(_) -> Err("invalid derivation index")
    Ok(output)
  end
end

fn child(node :: Bytes, index :: Int) -> Bytes!String do
  let data = joined(joined(Bytes.from_hex("00")?, part(node, 0)?)?, hardened(index)?)?
  issuer_hmac_sha512(part(node, 32)?, data)
end

fn walk(node :: Bytes, path :: List<Int>, position :: Int) -> Bytes!String do
  if position >= List.length(path) do
    Ok(node)
  else
    walk(child(node, List.get(path, position))?, path, position + 1)
  end
end

## SLIP-0010 Ed25519: (private key, chain code) at `path`; every index is
## hardened and must be below 2^31.

pub fn issuer_slip10(seed :: Bytes, path :: List<Int>) -> (Bytes, Bytes)!String do
  if List.any(path, fn index -> index < 0 || index >= 2147483648 end) do
    Err("invalid derivation index")
  else if Bytes.length(seed) < 16 || Bytes.length(seed) > 64 do
    Err("a deposit seed has 16 to 64 bytes")
  else
    let node = walk(issuer_hmac_sha512(Bytes.from_utf8("ed25519 seed"), seed)?, path, 0)?
    Ok((part(node, 0)?, part(node, 32)?))
  end
end

## The key at m/44'/501'/index'/0': quote deposits below the fee payer's
## index, and the fee payer itself.

pub fn issuer_deposit_key(seed :: Bytes, index :: Int) -> DepositKey!String do
  if index < 0 || index > issuer_fee_payer_index() do
    Err("invalid deposit index")
  else
    let (secret, _chain) = issuer_slip10(seed, [44, 501, index, 0])?
    let pair = case Crypto.signing_from_seed(secret) do
      Err(_) -> Err("deposit key derivation failed")
      Ok(value)
    end?
    Ok(DepositKey {
      index: index,
      secret: secret,
      public_key: pair.public_key.bytes,
      address: Bytes.to_base58(pair.public_key.bytes)
    })
  end
end

## Signs a message with a derived key (Ed25519, as Solana does).

pub fn issuer_sign(key :: DepositKey, message :: Bytes) -> Bytes!String do
  let pair = case Crypto.signing_from_seed(key.secret) do
    Err(_) -> Err("deposit key unusable")
    Ok(value)
  end?
  case Crypto.sign(pair.private_key, message) do
    Err(_) -> Err("deposit signing failed")
    Ok(signature) -> Ok(signature.bytes)
  end
end
