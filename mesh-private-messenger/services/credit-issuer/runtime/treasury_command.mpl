pub type TreasuryCommand do
  TreasuryProvision
  TreasuryStatus
  TreasuryRun
  TreasuryRefund(Bytes, Bytes)
  TreasuryWeekly(U64, Int)
  TreasuryWeeklyPolicy(U64, Int, Int)
  TreasuryBurnRequest(U64, U64)
  TreasuryBurnReconcile(Bytes)
  TreasuryBurnExpireRequest(U64)
  TreasuryFundingRequest(U64)
  TreasuryFundingReconcile(Bytes)
  TreasuryRetryBatch(Bytes)
  TreasuryRetryMovement(Bytes)
end

fn identifier(value :: String) -> Bytes!String do
  let bytes = Bytes.from_hex(value)?
  if Bytes.length(bytes) != 32 || Bytes.to_hex(bytes) != value do
    return Err("invalid_treasury_identifier")
  end
  Ok(bytes)
end

fn number(value :: String) -> U64!String do
  let parsed = U64.parse(value)?
  if U64.to_string(parsed) != value do
    return Err("invalid_treasury_number")
  end
  Ok(parsed)
end

pub fn parse_treasury_command(args :: List<String>) -> TreasuryCommand!String do
  if List.length(args) < 3 || List.get(args, 1) != "treasury" do
    return Err("invalid_treasury_command")
  end
  let operation = List.get(args, 2)
  if List.length(args) == 3 do
    return case operation do
      "provision" -> Ok(TreasuryProvision)
      "status" -> Ok(TreasuryStatus)
      "run-once" -> Ok(TreasuryRun)
      _ -> Err("invalid_treasury_command")
    end
  end
  if List.length(args) == 4 do
    let value = List.get(args, 3)
    return case operation do
      "burn-reconcile" -> Ok(TreasuryBurnReconcile(identifier(value)?))
      "burn-expire-request" -> Ok(TreasuryBurnExpireRequest(number(value)?))
      "funding-request" -> Ok(TreasuryFundingRequest(number(value)?))
      "funding-reconcile" -> Ok(TreasuryFundingReconcile(identifier(value)?))
      "retry-batch" -> Ok(TreasuryRetryBatch(identifier(value)?))
      "retry-movement" -> Ok(TreasuryRetryMovement(identifier(value)?))
      _ -> Err("invalid_treasury_command")
    end
  end
  if List.length(args) == 5 && operation == "burn-request" do
    return Ok(TreasuryBurnRequest(number(List.get(args, 3))?, number(List.get(args, 4))?))
  end
  if List.length(args) == 5 && operation == "refund" do
    let signature_text = List.get(args, 4)
    let signature = Bytes.from_base58(signature_text)?
    if Bytes.length(signature) != 64 || Bytes.to_base58(signature) != signature_text do
      return Err("invalid_treasury_payment_signature")
    end
    return Ok(TreasuryRefund(identifier(List.get(args, 3))?, signature))
  end
  if List.length(args) == 5 && operation == "weekly" do
    let asset = case List.get(args, 4) do
      "usdc" -> 0
      "sol" -> 1
      _ -> return Err("invalid_treasury_asset")
    end
    return Ok(TreasuryWeekly(number(List.get(args, 3))?, asset))
  end
  if List.length(args) == 6 && operation == "weekly-policy" do
    let asset = case List.get(args, 4) do
      "usdc" -> 0
      "sol" -> 1
      _ -> return Err("invalid_treasury_asset")
    end
    let version = case List.get(args, 5) do
      "1" -> 1
      "2" -> 2
      _ -> return Err("invalid_credit_revenue_policy")
    end
    return Ok(TreasuryWeeklyPolicy(number(List.get(args, 3))?, asset, version))
  end
  Err("invalid_treasury_command")
end
