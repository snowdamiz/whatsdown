from Payment.BtcConversion import BtcConversionPlan, btc_conversion_id
from Payment.BtcConversionConfig import BtcConversionConfig, btc_conversion_profile
from Payment.KrakenAuth import KrakenSignedRequest
from Storage.LightningRevenue import LightningRevenueWeek, load_lightning_revenue_week
from Storage.Lightning import lightning_backend_hash

pub struct BtcConversionIntent do
  intent_id :: Bytes
  batch_id :: U64
  bucket :: Int
  treasury_config_hash :: Bytes
  profile_hash :: Bytes
  plan :: BtcConversionPlan
  reserved_at :: U64
  stage :: String
  revision :: U64
  order_draft_revision :: U64
  withdrawal_draft_revision :: U64
  invoice_hash :: Bytes
  order_id :: String
  withdrawal_id :: String
end
fn text(value :: DbValue) -> String!String do
  case value do Text(output)->Ok(output) Null->Ok("") _->Err("invalid_btc_conversion_row") end
end
fn binary(value :: DbValue) -> Bytes!String do
  case value do Binary(output)->Ok(output) Null->Ok(Bytes.empty()) _->Err("invalid_btc_conversion_row") end
end
fn n(row :: Map<String,DbValue>, name :: String) -> U64!String do U64.parse(text(Map.get(row,name))?) end
fn optional_number(row :: Map<String,DbValue>,name :: String) -> U64!String do
  case Map.get(row,name) do Null->U64.parse("0") Text(value)->U64.parse(value) _->Err("invalid_btc_draft_revision") end
end
fn from_row(row :: Map<String,DbValue>) -> BtcConversionIntent!String do
  let p = BtcConversionPlan{source_msat:n(row,"source_msat")?,invoice_msat:n(row,"invoice_msat")?,trade_sats:n(row,"trade_sats")?,provider_btc_reserve_msat:n(row,"provider_btc_reserve_msat")?,routing_fee_limit_msat:n(row,"routing_fee_limit_msat")?,dust_msat:n(row,"dust_msat")?,minimum_output_usdc:n(row,"minimum_output_usdc")?,minimum_gross_usdc:n(row,"minimum_gross_usdc")?,limit_price_micros:n(row,"limit_price_micros")?,reference_price_micros:n(row,"reference_price_micros")?,reference_at:n(row,"reference_at")?}
  Ok(BtcConversionIntent{intent_id:binary(Map.get(row,"intent_id"))?,batch_id:n(row,"batch_id")?,bucket:U64.to_int(n(row,"bucket")?)?,treasury_config_hash:binary(Map.get(row,"treasury_config_hash"))?,profile_hash:binary(Map.get(row,"profile_hash"))?,plan:p,reserved_at:n(row,"reserved_at")?,stage:text(Map.get(row,"stage"))?,revision:n(row,"revision")?,order_draft_revision:optional_number(row,"order_draft_revision")?,withdrawal_draft_revision:optional_number(row,"withdrawal_draft_revision")?,invoice_hash:binary(Map.get(row,"invoice_hash"))?,order_id:text(Map.get(row,"order_id"))?,withdrawal_id:text(Map.get(row,"withdrawal_id"))?})
end
fn columns() -> String do
  "intent_id,batch_id::text,bucket::text,profile_hash,treasury_config_hash,source_msat::text,invoice_msat::text,trade_sats::text,provider_btc_reserve_msat::text,routing_fee_limit_msat::text,dust_msat::text,minimum_output_usdc::text,minimum_gross_usdc::text,limit_price_micros::text,reference_price_micros::text,reference_at::text,reserved_at::text,stage,revision::text,order_draft_revision::text,withdrawal_draft_revision::text,invoice_hash,order_id,withdrawal_id"
end
pub fn load_btc_conversion(conn :: borrow PgConn, config :: BtcConversionConfig,
  batch :: U64, bucket :: Int) -> Option<BtcConversionIntent>!String do
  if bucket!=0 && bucket!=1 do return Err("btc_operations_not_authorized") end
  let rows = Pg.query_values(conn,"SELECT "<>columns()<>" FROM issuer_btc_conversion_intents WHERE batch_id=$1::bigint AND bucket=$2::smallint",[Text(U64.to_string(batch)),Text(Int.to_string(bucket))])?
  if List.length(rows)==0 do return Ok(None) end
  let record = from_row(List.head(rows))?
  if record.profile_hash != btc_conversion_profile(config)? || record.treasury_config_hash!=config.treasury_config_hash do return Err("btc_conversion_profile_changed") end
  # Recovery is intentionally independent of pending admission/output use.
  Ok(Some(record))
end
pub fn btc_conversion_source(conn :: borrow PgConn, config :: BtcConversionConfig,
  batch :: U64, bucket :: Int, now :: U64) -> LightningRevenueWeek!String do
  if bucket!=0 && bucket!=1 do return Err("btc_operations_not_authorized") end
  let week = load_lightning_revenue_week(conn,batch)?
  if week.backend_hash != lightning_backend_hash(config.backend)?
    || U64.compare(week.week,U64.divide(now,U64.parse("604800")?)?)>=0 do return Err("btc_original_week_scope_mismatch") end
  let source = if bucket==0 do week.allocation.witness else week.allocation.burn end
  if source==U64.parse("0")? do return Err("btc_original_liability_empty") end
  let domain = Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-lightning-week-members-v1"))<>Bytes.to_hex(week.backend_hash)<>Bytes.to_hex(Bytes.write_uint_le(U64.to_string(week.week),8)?)<>Bytes.to_hex(week.allocation.policy_hash))?
  let rows = Pg.query_values(conn,"SELECT COALESCE(SUM(e.received_msat),0)::text AS amount,sha256($2::bytea||COALESCE(string_agg(e.quote_id||convert_to(lpad(e.received_msat::text,20,'0')||lpad(e.settled_at::text,20,'0'),'UTF8'),''::bytea ORDER BY e.quote_id),''::bytea)) AS membership_hash FROM issuer_lightning_weekly_events m JOIN issuer_lightning_revenue e USING(quote_id) WHERE m.batch_id=$1::bigint AND e.backend_hash=$3 AND e.policy_version=$4::smallint AND e.policy_hash=$5",[Text(U64.to_string(batch)),Binary(domain),Binary(week.backend_hash),Text(Int.to_string(week.allocation.policy)),Binary(week.allocation.policy_hash)])?
  if List.length(rows)!=1 || n(List.head(rows),"amount")?!=week.amount || binary(Map.get(List.head(rows),"membership_hash"))?!=week.membership_hash do return Err("btc_original_membership_mismatch") end
  let existing=Pg.query_values(conn,"SELECT intent_id FROM issuer_btc_conversion_intents WHERE batch_id=$1::bigint AND bucket=$2::smallint",[Text(U64.to_string(batch)),Text(Int.to_string(bucket))])?
  if List.length(existing)!=0 do return Err("btc_original_liability_already_reserved") end
  Ok(week)
end
pub fn reserve_btc_conversion(conn :: borrow PgConn, config :: BtcConversionConfig,
  batch :: U64, bucket :: Int, plan :: BtcConversionPlan, now :: U64) -> BtcConversionIntent!String do
  Pg.query(conn,"SELECT pg_advisory_xact_lock(1835365494)",[])?
  case load_btc_conversion(conn,config,batch,bucket)? do Some(value)->return Ok(value) None->nil end
  let week=btc_conversion_source(conn,config,batch,bucket,now)?
  let source=if bucket==0 do week.allocation.witness else week.allocation.burn end
  if plan.source_msat!=source || U64.compare(now,plan.reference_at)<0 || U64.compare(U64.subtract(now,plan.reference_at)?,U64.parse("60")?)>0 do return Err("btc_reservation_plan_mismatch") end
  let profile=btc_conversion_profile(config)?
  let id=btc_conversion_id(profile,batch,week.allocation.policy_hash,week.membership_hash,week.backend_hash,bucket,source)?
  Pg.execute_values(conn,"INSERT INTO issuer_btc_conversion_intents(intent_id,batch_id,bucket,profile_hash,treasury_config_hash,policy_version,policy_hash,membership_hash,backend_hash,source_msat,invoice_msat,trade_sats,provider_btc_reserve_msat,routing_fee_limit_msat,dust_msat,minimum_output_usdc,minimum_gross_usdc,limit_price_micros,reference_price_micros,reference_at,reserved_at) VALUES($1,$2::bigint,$3::smallint,$4,$21,$5::smallint,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric,$12::numeric,$13::numeric,$14::smallint,$15::numeric,$16::numeric,$17::numeric,$18::numeric,$19::numeric,$20::numeric)",[Binary(id),Text(U64.to_string(batch)),Text(Int.to_string(bucket)),Binary(profile),Text(Int.to_string(week.allocation.policy)),Binary(week.allocation.policy_hash),Binary(week.membership_hash),Binary(week.backend_hash),Text(U64.to_string(source)),Text(U64.to_string(plan.invoice_msat)),Text(U64.to_string(plan.trade_sats)),Text(U64.to_string(plan.provider_btc_reserve_msat)),Text(U64.to_string(plan.routing_fee_limit_msat)),Text(U64.to_string(plan.dust_msat)),Text(U64.to_string(plan.minimum_output_usdc)),Text(U64.to_string(plan.minimum_gross_usdc)),Text(U64.to_string(plan.limit_price_micros)),Text(U64.to_string(plan.reference_price_micros)),Text(U64.to_string(plan.reference_at)),Text(U64.to_string(now)),Binary(config.treasury_config_hash)])?
  case load_btc_conversion(conn,config,batch,bucket)? do Some(value)->Ok(value) None->Err("btc_reservation_not_committed") end
end
pub fn transition_btc_conversion(conn :: borrow PgConn, before :: BtcConversionIntent,
  next :: String, invoice_hash :: Bytes, order_id :: String, withdrawal_id :: String) -> Result<(),String> do
  let rows=Pg.query_values(conn,"UPDATE issuer_btc_conversion_intents SET stage=$3,revision=revision+1,invoice_hash=CASE WHEN octet_length($4::bytea)=0 THEN invoice_hash ELSE $4 END,order_id=CASE WHEN $5='' THEN order_id ELSE $5 END,withdrawal_id=CASE WHEN $6='' THEN withdrawal_id ELSE $6 END WHERE intent_id=$1 AND revision=$2::bigint AND stage=$7 RETURNING intent_id",[Binary(before.intent_id),Text(U64.to_string(before.revision)),Text(next),Binary(invoice_hash),Text(order_id),Text(withdrawal_id),Text(before.stage)])?
  if List.length(rows)!=1 do Err("btc_conversion_conflict") else Ok(nil) end
end
pub fn btc_artifact(conn :: borrow PgConn, id :: Bytes, kind :: String) -> String!String do
  let rows=Pg.query_values(conn,"SELECT body,body_sha256 FROM issuer_btc_conversion_artifacts WHERE intent_id=$1 AND kind=$2",[Binary(id),Text(kind)])?
  if List.length(rows)!=1 do return Err("btc_artifact_missing") end
  let body=text(Map.get(List.head(rows),"body"))?
  if Crypto.sha256(Bytes.from_utf8(body))!=binary(Map.get(List.head(rows),"body_sha256"))? do return Err("btc_artifact_corrupt") end
  Ok(body)
end
pub fn store_btc_artifact(conn :: borrow PgConn,id :: Bytes,kind :: String,body :: String) -> Result<(),String> do
  Pg.execute_values(conn,"INSERT INTO issuer_btc_conversion_artifacts(intent_id,kind,body,body_sha256) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",[Binary(id),Text(kind),Text(body),Binary(Crypto.sha256(Bytes.from_utf8(body)))])?
  if btc_artifact(conn,id,kind)?!=body do return Err("btc_artifact_conflict") end
  Ok(nil)
end
pub fn store_btc_request(conn :: borrow PgConn,id :: Bytes,kind :: String,method :: String,
  request :: KrakenSignedRequest,now :: U64) -> Result<(),String> do
  Pg.execute_values(conn,"INSERT INTO issuer_btc_conversion_requests VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9::numeric)",[Binary(id),Text(kind),Text(method),Text(request.path),Text(request.nonce),Text(request.content_type),Text(request.body),Text(request.signature),Text(U64.to_string(now))])?
  Ok(nil)
end
pub fn load_btc_request(conn :: borrow PgConn,id :: Bytes,kind :: String) -> KrakenSignedRequest!String do
  let rows=Pg.query_values(conn,"SELECT path,nonce::text,content_type,body,signature FROM issuer_btc_conversion_requests WHERE intent_id=$1 AND kind=$2",[Binary(id),Text(kind)])?
  if List.length(rows)!=1 do return Err("btc_request_missing") end
  let row=List.head(rows)
  Ok(KrakenSignedRequest{path:text(Map.get(row,"path"))?,nonce:text(Map.get(row,"nonce"))?,content_type:text(Map.get(row,"content_type"))?,body:text(Map.get(row,"body"))?,signature:text(Map.get(row,"signature"))?})
end

# Persist nonce+exclusive API-key lease before any HTTP. A crashed holder expires;
# effect state remains unknown and cannot be reset to send a duplicate request.
pub fn reserve_kraken_nonce(conn :: borrow PgConn,api_key :: String,lease :: Bytes,
  now_ms :: U64) -> U64!String do
  if Bytes.length(lease)!=32 do return Err("invalid_btc_nonce_lease") end
  let key=Crypto.sha256(Bytes.from_utf8(api_key))
  let until=U64.add(now_ms,U64.parse("60000")?)?
  let rows=Pg.query_values(conn,"INSERT INTO issuer_btc_kraken_nonces(api_key_hash,value,lease_id,lease_until,observed_at) VALUES($1,$2::numeric,$3,$4::numeric,$2::numeric) ON CONFLICT(api_key_hash) DO UPDATE SET value=GREATEST(issuer_btc_kraken_nonces.value+1,EXCLUDED.value),lease_id=EXCLUDED.lease_id,lease_until=EXCLUDED.lease_until,observed_at=EXCLUDED.observed_at WHERE issuer_btc_kraken_nonces.lease_until<=$2::numeric AND issuer_btc_kraken_nonces.observed_at<=$2::numeric AND issuer_btc_kraken_nonces.value<18446744073709551615 RETURNING value::text",[Binary(key),Text(U64.to_string(now_ms)),Binary(lease),Text(U64.to_string(until))])?
  if List.length(rows)!=1 do return Err("btc_api_key_busy_or_clock_regressed") end
  n(List.head(rows),"value")
end
pub fn release_kraken_nonce(conn :: borrow PgConn,api_key :: String,lease :: Bytes) -> Result<(),String> do
  Pg.execute_values(conn,"UPDATE issuer_btc_kraken_nonces SET lease_until=0,lease_id=NULL WHERE api_key_hash=$1 AND lease_id=$2",[Binary(Crypto.sha256(Bytes.from_utf8(api_key))),Binary(lease)])?
  Ok(nil)
end

pub fn reserve_btc_output_use(conn :: borrow PgConn, value :: BtcConversionIntent,
  operation_id :: Bytes) -> Result<(),String> do
  Pg.query_values(conn,"SELECT intent_id FROM issuer_btc_conversion_intents WHERE intent_id=$1 FOR UPDATE",[Binary(value.intent_id)])?
  let active=Pg.query_values(conn,"SELECT operation_id,bucket::text FROM issuer_btc_conversion_output_uses WHERE intent_id=$1 AND NOT released",[Binary(value.intent_id)])?
  if List.length(active)==1 do
    if binary(Map.get(List.head(active),"operation_id"))?!=operation_id || n(List.head(active),"bucket")?!=U64.parse(Int.to_string(value.bucket))? do return Err("btc_output_already_reserved") end
    return Ok(nil)
  end
  let rows=Pg.query_values(conn,"INSERT INTO issuer_btc_conversion_output_uses(intent_id,bucket,operation_id,receipt_hash) SELECT intent_id,$2::smallint,$3,sha256(receipt) FROM issuer_btc_conversion_outputs WHERE intent_id=$1 ON CONFLICT DO NOTHING RETURNING intent_id",[Binary(value.intent_id),Text(Int.to_string(value.bucket)),Binary(operation_id)])?
  if List.length(rows)==0 do
    let existing=Pg.query_values(conn,"SELECT operation_id FROM issuer_btc_conversion_output_uses WHERE intent_id=$1 AND NOT released",[Binary(value.intent_id)])?
    if List.length(existing)!=1 || binary(Map.get(List.head(existing),"operation_id"))?!=operation_id do return Err("btc_output_already_reserved") end
    return Ok(nil)
  end
  transition_btc_conversion(conn,value,"output-reserved",Bytes.empty(),"","")
end

pub struct BtcConversionDraft do
  revision :: U64
  observed_at :: U64
  body :: String
  sha256 :: Bytes
end
pub fn store_btc_draft(conn :: borrow PgConn,value :: BtcConversionIntent,
  kind :: String,body :: String,at :: U64) -> Result<(),String> do
  if kind!="order" && kind!="withdrawal" do return Err("invalid_btc_draft_kind") end
  let revision=U64.add(value.revision,U64.parse("1")?)?
  Pg.execute_values(conn,"INSERT INTO issuer_btc_conversion_drafts VALUES($1,$2,$3::bigint,$4::numeric,$5,$6)",[Binary(value.intent_id),Text(kind),Text(U64.to_string(revision)),Text(U64.to_string(at)),Text(body),Binary(Crypto.sha256(Bytes.from_utf8(body)))])?
  let query=if kind=="order" do
    "UPDATE issuer_btc_conversion_intents SET stage='order-ready',revision=revision+1,order_draft_revision=revision+1 WHERE intent_id=$1 AND revision=$2::bigint AND stage=$3 RETURNING intent_id"
  else
    "UPDATE issuer_btc_conversion_intents SET stage='withdrawal-ready',revision=revision+1,withdrawal_draft_revision=revision+1 WHERE intent_id=$1 AND revision=$2::bigint AND stage=$3 RETURNING intent_id"
  end
  let rows=Pg.query_values(conn,query,[Binary(value.intent_id),Text(U64.to_string(value.revision)),Text(value.stage)])?
  if List.length(rows)!=1 do return Err("btc_draft_refresh_conflict") end
  Ok(nil)
end
pub fn load_btc_draft(conn :: borrow PgConn,value :: BtcConversionIntent,
  kind :: String) -> BtcConversionDraft!String do
  let revision=if kind=="order" do value.order_draft_revision else if kind=="withdrawal" do value.withdrawal_draft_revision else return Err("invalid_btc_draft_kind") end
  let rows=Pg.query_values(conn,"SELECT observed_at::text,body,body_sha256 FROM issuer_btc_conversion_drafts WHERE intent_id=$1 AND kind=$2 AND revision=$3::bigint",[Binary(value.intent_id),Text(kind),Text(U64.to_string(revision))])?
  if List.length(rows)!=1 do return Err("btc_selected_draft_missing") end
  let row=List.head(rows)
  let body=text(Map.get(row,"body"))?
  let hash=binary(Map.get(row,"body_sha256"))?
  if Crypto.sha256(Bytes.from_utf8(body))!=hash do return Err("btc_selected_draft_corrupt") end
  Ok(BtcConversionDraft{revision:revision,observed_at:n(row,"observed_at")?,body:body,sha256:hash})
end
