-- Dedicated BTC conversion journal. Original Lightning weekly liabilities stay
-- millisatoshis; these IDs never enter the Solana weekly batch namespace.
CREATE TABLE issuer_btc_conversion_intents (
 intent_id BYTEA PRIMARY KEY CHECK(octet_length(intent_id)=32),
 batch_id BIGINT NOT NULL REFERENCES issuer_lightning_weekly(batch_id),
 bucket SMALLINT NOT NULL CHECK(bucket IN(0,1)),
 profile_hash BYTEA NOT NULL CHECK(octet_length(profile_hash)=32),
 treasury_config_hash BYTEA NOT NULL CHECK(octet_length(treasury_config_hash)=32),
 policy_version SMALLINT NOT NULL,
 policy_hash BYTEA NOT NULL CHECK(octet_length(policy_hash)=32),
 membership_hash BYTEA NOT NULL CHECK(octet_length(membership_hash)=32),
 backend_hash BYTEA NOT NULL CHECK(octet_length(backend_hash)=32),
 source_msat NUMERIC(20,0) NOT NULL CHECK(source_msat>0 AND source_msat<=18446744073709551615),
 invoice_msat NUMERIC(20,0) NOT NULL CHECK(invoice_msat>0 AND mod(invoice_msat,1000)=0),
 trade_sats NUMERIC(20,0) NOT NULL CHECK(trade_sats>0),
 provider_btc_reserve_msat NUMERIC(20,0) NOT NULL CHECK(provider_btc_reserve_msat>=0),
 routing_fee_limit_msat NUMERIC(20,0) NOT NULL CHECK(routing_fee_limit_msat>=0),
 dust_msat SMALLINT NOT NULL CHECK(dust_msat BETWEEN 0 AND 999),
 minimum_output_usdc NUMERIC(20,0) NOT NULL CHECK(minimum_output_usdc>0 AND minimum_output_usdc<=18446744073709551615),
 minimum_gross_usdc NUMERIC(20,0) NOT NULL CHECK(minimum_gross_usdc>=minimum_output_usdc AND minimum_gross_usdc<=18446744073709551615),
 limit_price_micros NUMERIC(20,0) NOT NULL CHECK(limit_price_micros>0 AND limit_price_micros<=18446744073709551615),
 reference_price_micros NUMERIC(20,0) NOT NULL CHECK(reference_price_micros>=limit_price_micros AND reference_price_micros<=18446744073709551615),
 reference_at NUMERIC(20,0) NOT NULL CHECK(reference_at>0),
 reserved_at NUMERIC(20,0) NOT NULL CHECK(reserved_at>=reference_at AND reserved_at-reference_at<=60),
 stage TEXT NOT NULL DEFAULT 'reserved' CHECK(stage IN('reserved','invoice-unknown','invoice-ready','payment-unknown','delivered','order-ready','order-unknown','order-known','converted','withdrawal-ready','withdrawal-unknown','withdrawal-known','arrived','output-reserved','held')),
 revision BIGINT NOT NULL DEFAULT 0 CHECK(revision>=0),
 order_draft_revision BIGINT,
 withdrawal_draft_revision BIGINT,
 order_draft_kind TEXT GENERATED ALWAYS AS ('order') STORED,
 withdrawal_draft_kind TEXT GENERATED ALWAYS AS ('withdrawal') STORED,
 invoice_hash BYTEA UNIQUE CHECK(octet_length(invoice_hash)=32),
 order_id TEXT UNIQUE CHECK(length(order_id) BETWEEN 1 AND 64),
 withdrawal_id TEXT UNIQUE CHECK(length(withdrawal_id) BETWEEN 1 AND 64),
 provider_credit_status TEXT NOT NULL DEFAULT 'not-independently-proven' CHECK(provider_credit_status='not-independently-proven'),
 UNIQUE(batch_id,bucket),
 FOREIGN KEY(policy_version,policy_hash) REFERENCES issuer_revenue_policies(policy_version,policy_hash),
 CHECK(source_msat=invoice_msat+routing_fee_limit_msat+dust_msat),
 CHECK(trade_sats*1000+provider_btc_reserve_msat=invoice_msat)
);
CREATE FUNCTION issuer_btc_conversion_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_lightning_weekly b WHERE b.batch_id=NEW.batch_id
   AND b.backend_hash=NEW.backend_hash AND b.policy_version=NEW.policy_version
   AND b.policy_hash=NEW.policy_hash AND b.membership_hash=NEW.membership_hash
   AND b.week<trunc(NEW.reserved_at/604800)
   AND NEW.source_msat=CASE WHEN NEW.bucket=0 THEN b.witness ELSE b.burn END) THEN
   RAISE EXCEPTION 'btc_original_liability_mismatch';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_conversion_source BEFORE INSERT ON issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION issuer_btc_conversion_source();

CREATE FUNCTION issuer_btc_conversion_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(OLD)-ARRAY['stage','revision','invoice_hash','order_id','withdrawal_id','order_draft_revision','withdrawal_draft_revision','order_draft_kind','withdrawal_draft_kind'])<>
    (to_jsonb(NEW)-ARRAY['stage','revision','invoice_hash','order_id','withdrawal_id','order_draft_revision','withdrawal_draft_revision','order_draft_kind','withdrawal_draft_kind'])
    OR NEW.revision<>OLD.revision+1
    OR (OLD.invoice_hash IS NOT NULL AND NEW.invoice_hash IS DISTINCT FROM OLD.invoice_hash)
    OR (OLD.order_id IS NOT NULL AND NEW.order_id IS DISTINCT FROM OLD.order_id)
    OR (OLD.withdrawal_id IS NOT NULL AND NEW.withdrawal_id IS DISTINCT FROM OLD.withdrawal_id)
    OR (CASE WHEN OLD.stage IN('delivered','order-ready') AND NEW.stage='order-ready' THEN NEW.order_draft_revision IS DISTINCT FROM NEW.revision ELSE NEW.order_draft_revision IS DISTINCT FROM OLD.order_draft_revision END)
    OR (CASE WHEN OLD.stage IN('converted','withdrawal-ready') AND NEW.stage='withdrawal-ready' THEN NEW.withdrawal_draft_revision IS DISTINCT FROM NEW.revision ELSE NEW.withdrawal_draft_revision IS DISTINCT FROM OLD.withdrawal_draft_revision END)
    OR NOT((NEW.stage='held'  AND OLD.stage NOT IN('output-reserved','held'))
      OR(OLD.stage='reserved' AND NEW.stage='invoice-unknown')
      OR(OLD.stage='invoice-unknown' AND NEW.stage='invoice-ready')
      OR(OLD.stage='invoice-ready' AND NEW.stage='payment-unknown')
      OR(OLD.stage='payment-unknown' AND NEW.stage='delivered')
      OR(OLD.stage IN('delivered','order-ready') AND NEW.stage='order-ready')
      OR(OLD.stage='order-ready' AND NEW.stage='order-unknown')
      OR(OLD.stage='order-unknown' AND NEW.stage IN('order-known','converted'))
      OR(OLD.stage='order-known' AND NEW.stage='converted')
      OR(OLD.stage IN('converted','withdrawal-ready') AND NEW.stage='withdrawal-ready')
      OR(OLD.stage='withdrawal-ready' AND NEW.stage='withdrawal-unknown')
      OR(OLD.stage='withdrawal-unknown' AND NEW.stage='withdrawal-known')
      OR(OLD.stage='withdrawal-known' AND NEW.stage='arrived')
      OR(OLD.stage='arrived' AND NEW.stage='output-reserved')
      OR(OLD.stage='output-reserved' AND NEW.stage='arrived' AND NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_output_uses u WHERE u.intent_id=OLD.intent_id AND NOT u.released) AND EXISTS(SELECT 1 FROM issuer_btc_conversion_output_uses u WHERE u.intent_id=OLD.intent_id AND u.released))) THEN
   RAISE EXCEPTION 'btc_conversion_transition_refused';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_conversion_transition BEFORE UPDATE ON issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION issuer_btc_conversion_transition();

-- Nonces belong to the actual API key, never a resettable profile/version.
CREATE TABLE issuer_btc_kraken_nonces (
 api_key_hash BYTEA PRIMARY KEY CHECK(octet_length(api_key_hash)=32),
 value NUMERIC(20,0) NOT NULL CHECK(value>=0 AND value<=18446744073709551615),
 lease_id BYTEA CHECK(octet_length(lease_id)=32),
 lease_until NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK(lease_until>=0 AND lease_until<=18446744073709551615),
 observed_at NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK(observed_at>=0 AND observed_at<=18446744073709551615)
);
CREATE TABLE issuer_btc_conversion_requests (
 intent_id BYTEA NOT NULL REFERENCES issuer_btc_conversion_intents(intent_id),
 kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 96),
 method TEXT NOT NULL CHECK(method IN('GET','POST')),
 path TEXT NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 4096),
 nonce NUMERIC(20,0) NOT NULL CHECK(nonce>=0 AND nonce<=18446744073709551615),
 content_type TEXT NOT NULL CHECK(length(content_type)<=128),
 body TEXT NOT NULL CHECK(octet_length(body)<=16384),
 signature TEXT NOT NULL CHECK(length(signature)<=128),
 created_at NUMERIC(20,0) NOT NULL CHECK(created_at>0),
 PRIMARY KEY(intent_id,kind)
);
CREATE TABLE issuer_btc_conversion_artifacts (
 intent_id BYTEA NOT NULL REFERENCES issuer_btc_conversion_intents(intent_id),
 kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 96),
 body TEXT NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 262144),
 body_sha256 BYTEA NOT NULL CHECK(octet_length(body_sha256)=32),
 CHECK(body_sha256=sha256(convert_to(body,'UTF8'))),
 PRIMARY KEY(intent_id,kind)
);
CREATE FUNCTION issuer_btc_artifact_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable_btc_conversion_artifact'; END;
$$;
CREATE TRIGGER issuer_btc_request_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_requests FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();
CREATE TRIGGER issuer_btc_artifact_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_artifacts FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();

-- Only independently checked finalized USDC arrival enters this table.
-- Its receipt includes the disjoint BTC conversion/profile/transaction identity.
CREATE TABLE issuer_btc_conversion_outputs (
 intent_id BYTEA PRIMARY KEY REFERENCES issuer_btc_conversion_intents(intent_id),
 mint BYTEA NOT NULL CHECK(octet_length(mint)=32),
 owner BYTEA NOT NULL CHECK(octet_length(owner)=32),
 custody BYTEA NOT NULL CHECK(octet_length(custody)=32),
 amount NUMERIC(20,0) NOT NULL CHECK(amount>0 AND amount<=18446744073709551615),
 transaction_signature BYTEA NOT NULL CHECK(octet_length(transaction_signature)=64),
 receipt BYTEA NOT NULL UNIQUE CHECK(octet_length(receipt)=340 AND substring(receipt from 1 for 4)=decode('4d434232','hex')),
 UNIQUE(transaction_signature,custody)
);
CREATE TRIGGER issuer_btc_output_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_outputs FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();
CREATE TABLE issuer_btc_conversion_output_uses (
 intent_id BYTEA NOT NULL REFERENCES issuer_btc_conversion_outputs(intent_id),
 bucket SMALLINT NOT NULL CHECK(bucket IN(0,1)),
 operation_id BYTEA NOT NULL CHECK(octet_length(operation_id)=32),
 receipt_hash BYTEA NOT NULL CHECK(octet_length(receipt_hash)=32),
 released BOOLEAN NOT NULL DEFAULT false,
 expiry_receipt BYTEA CHECK(octet_length(expiry_receipt)=256),
 burn_intent_id BYTEA GENERATED ALWAYS AS (CASE WHEN bucket=1 THEN operation_id ELSE NULL END) STORED REFERENCES issuer_treasury_burn_intents(intent_id),
 PRIMARY KEY(intent_id,operation_id),
 CHECK((NOT released AND expiry_receipt IS NULL) OR (released AND bucket=1 AND expiry_receipt IS NOT NULL))
);
CREATE UNIQUE INDEX issuer_btc_output_active_use ON issuer_btc_conversion_output_uses(intent_id) WHERE NOT released;
CREATE FUNCTION issuer_btc_output_use_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i JOIN issuer_btc_conversion_outputs o USING(intent_id)
   WHERE i.intent_id=NEW.intent_id AND i.bucket=NEW.bucket AND i.stage='arrived' AND NOT NEW.released
   AND NEW.receipt_hash=sha256(o.receipt) AND (NEW.bucket=0 OR EXISTS(SELECT 1 FROM issuer_treasury_burn_intents b WHERE b.intent_id=NEW.operation_id AND b.state=0 AND b.config_hash=i.treasury_config_hash AND b.payer=o.owner AND substring(b.profile from 37 for 32)=o.mint))) THEN RAISE EXCEPTION 'btc_output_use_mismatch'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_output_use_binding BEFORE INSERT ON issuer_btc_conversion_output_uses FOR EACH ROW EXECUTE FUNCTION issuer_btc_output_use_binding();
CREATE FUNCTION issuer_btc_output_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'UPDATE' OR OLD.released OR NOT NEW.released OR OLD.bucket<>1
   OR (to_jsonb(OLD)-ARRAY['released','expiry_receipt','burn_intent_id'])<>(to_jsonb(NEW)-ARRAY['released','expiry_receipt','burn_intent_id'])
   OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_intents b WHERE b.intent_id=OLD.operation_id
     AND b.state=2 AND b.expiry_receipt=NEW.expiry_receipt) THEN RAISE EXCEPTION 'btc_output_release_not_proven_unfunded'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_use_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_output_uses FOR EACH ROW EXECUTE FUNCTION issuer_btc_output_release();
-- Readable admission deferrals carry no conversion/effect authority. The exact
-- original liability remains pending; there is no implicit multi-week pooling.
CREATE TABLE issuer_btc_conversion_deferrals (
 batch_id BIGINT NOT NULL REFERENCES issuer_lightning_weekly(batch_id),
 bucket SMALLINT NOT NULL CHECK(bucket IN(0,1)),
 profile_hash BYTEA NOT NULL CHECK(octet_length(profile_hash)=32),
 reason TEXT NOT NULL CHECK(reason IN('below-minimum-order','full-fee-floor-unavailable','source-limit')),
 observed_at NUMERIC(20,0) NOT NULL CHECK(observed_at>0),
 PRIMARY KEY(batch_id,bucket,profile_hash)
);
CREATE TRIGGER issuer_btc_intent_no_delete BEFORE DELETE ON issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();
CREATE FUNCTION issuer_btc_output_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i WHERE i.intent_id=NEW.intent_id
   AND i.stage='withdrawal-known' AND NEW.amount>=i.minimum_output_usdc
   AND substring(NEW.receipt from 5 for 32)=NEW.intent_id AND substring(NEW.receipt from 37 for 32)=i.profile_hash
   AND substring(NEW.receipt from 69 for 64)=NEW.transaction_signature
   AND substring(NEW.receipt from 181 for 32)=NEW.mint AND substring(NEW.receipt from 213 for 32)=NEW.owner
   AND substring(NEW.receipt from 245 for 32)=NEW.custody
   AND substring(NEW.receipt from 277 for 32)=sha256(convert_to(i.withdrawal_id,'UTF8'))
   AND EXISTS(SELECT 1 FROM issuer_btc_conversion_drafts d WHERE d.intent_id=i.intent_id AND d.kind='order' AND d.revision=i.order_draft_revision AND d.body_sha256=substring(NEW.receipt from 309 for 32) AND NEW.amount>=(d.body::jsonb->>'minimum_output_usdc')::numeric)) THEN
   RAISE EXCEPTION 'btc_output_not_admitted';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_output_admission BEFORE INSERT ON issuer_btc_conversion_outputs FOR EACH ROW EXECUTE FUNCTION issuer_btc_output_admission();
-- These are retained liabilities of the same original bucket, not new USDC or
-- operations revenue. Only the separately finalized output can be handed off.
CREATE TABLE issuer_btc_conversion_accounting (
 intent_id BYTEA PRIMARY KEY REFERENCES issuer_btc_conversion_intents(intent_id),
 actual_routing_fee_msat NUMERIC(20,0) NOT NULL CHECK(actual_routing_fee_msat>=0),
 actual_btc_fee_msat NUMERIC(20,0) NOT NULL CHECK(actual_btc_fee_msat>=0),
 actual_usdc_fee_100ths NUMERIC(20,0) NOT NULL CHECK(actual_usdc_fee_100ths>=0),
 lnd_residual_msat NUMERIC(20,0) NOT NULL CHECK(lnd_residual_msat>=0),
 provider_btc_residual_msat NUMERIC(20,0) NOT NULL CHECK(provider_btc_residual_msat>=0),
 provider_usdc_residual_100ths SMALLINT NOT NULL CHECK(provider_usdc_residual_100ths BETWEEN 0 AND 99),
 provider_net_usdc NUMERIC(20,0) NOT NULL CHECK(provider_net_usdc>0 AND provider_net_usdc<=18446744073709551615)
);
CREATE FUNCTION issuer_btc_accounting_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i WHERE i.intent_id=NEW.intent_id AND i.stage IN('order-unknown','order-known')
  AND NEW.actual_routing_fee_msat<=i.routing_fee_limit_msat AND NEW.actual_btc_fee_msat<=i.provider_btc_reserve_msat
  AND NEW.lnd_residual_msat=i.routing_fee_limit_msat-NEW.actual_routing_fee_msat+i.dust_msat
  AND NEW.provider_btc_residual_msat=i.provider_btc_reserve_msat-NEW.actual_btc_fee_msat
  AND i.source_msat=i.trade_sats*1000+NEW.actual_btc_fee_msat+NEW.actual_routing_fee_msat+NEW.lnd_residual_msat+NEW.provider_btc_residual_msat) THEN RAISE EXCEPTION 'btc_actual_accounting_mismatch'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_accounting_binding BEFORE INSERT ON issuer_btc_conversion_accounting FOR EACH ROW EXECUTE FUNCTION issuer_btc_accounting_binding();
CREATE TRIGGER issuer_btc_accounting_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_accounting FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();

CREATE TABLE issuer_btc_conversion_drafts (
 intent_id BYTEA NOT NULL REFERENCES issuer_btc_conversion_intents(intent_id),
 kind TEXT NOT NULL CHECK(kind IN('order','withdrawal')),
 revision BIGINT NOT NULL CHECK(revision>0),
 observed_at NUMERIC(20,0) NOT NULL CHECK(observed_at>0),
 body TEXT NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 16384),
 body_sha256 BYTEA NOT NULL CHECK(octet_length(body_sha256)=32 AND body_sha256=sha256(convert_to(body,'UTF8'))),
 PRIMARY KEY(intent_id,kind,revision)
);
ALTER TABLE issuer_btc_conversion_intents
 ADD FOREIGN KEY(intent_id,order_draft_kind,order_draft_revision) REFERENCES issuer_btc_conversion_drafts(intent_id,kind,revision),
 ADD FOREIGN KEY(intent_id,withdrawal_draft_kind,withdrawal_draft_revision) REFERENCES issuer_btc_conversion_drafts(intent_id,kind,revision);
CREATE FUNCTION issuer_btc_draft_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i WHERE i.intent_id=NEW.intent_id AND NEW.revision=i.revision+1 AND
  ((NEW.kind='order' AND i.stage IN('delivered','order-ready')) OR (NEW.kind='withdrawal' AND i.stage IN('converted','withdrawal-ready')))) THEN RAISE EXCEPTION 'btc_draft_not_refreshable'; END IF;
 IF (SELECT COUNT(*) FROM issuer_btc_conversion_drafts d WHERE d.intent_id=NEW.intent_id AND d.kind=NEW.kind)>=32 THEN RAISE EXCEPTION 'btc_draft_capacity'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_draft_admission BEFORE INSERT ON issuer_btc_conversion_drafts FOR EACH ROW EXECUTE FUNCTION issuer_btc_draft_admission();
CREATE TRIGGER issuer_btc_draft_immutable BEFORE UPDATE OR DELETE ON issuer_btc_conversion_drafts FOR EACH ROW EXECUTE FUNCTION issuer_btc_artifact_immutable();
CREATE FUNCTION issuer_btc_request_capacity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT COUNT(*) FROM issuer_btc_conversion_requests r WHERE r.intent_id=NEW.intent_id)>=256 THEN RAISE EXCEPTION 'btc_request_capacity'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_request_capacity BEFORE INSERT ON issuer_btc_conversion_requests FOR EACH ROW EXECUTE FUNCTION issuer_btc_request_capacity();
