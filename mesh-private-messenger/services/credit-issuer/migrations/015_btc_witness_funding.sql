-- One permanent bucket-0 output reservation; epoch funding attempts never
-- release or reassign the original Lightning/BTC conversion liability.
CREATE TABLE issuer_btc_witness_funding (
 funding_id BYTEA PRIMARY KEY CHECK(octet_length(funding_id)=32),
 conversion_id BYTEA NOT NULL REFERENCES issuer_btc_conversion_outputs(intent_id),
 reservation_id BYTEA NOT NULL CHECK(octet_length(reservation_id)=32),
 receipt_hash BYTEA NOT NULL CHECK(octet_length(receipt_hash)=32),
 epoch NUMERIC(20,0) NOT NULL CHECK(epoch>=0 AND epoch<=18446744073709551615),
 program BYTEA NOT NULL CHECK(octet_length(program)=32),
 pool BYTEA NOT NULL CHECK(octet_length(pool)=32),
 state SMALLINT NOT NULL DEFAULT 0 CHECK(state IN(0,1,2)),
 receipt BYTEA CHECK(octet_length(receipt)=192 AND substring(receipt from 1 for 4)=decode('4d524601','hex')),
 expired_epoch NUMERIC(20,0) CHECK(expired_epoch>epoch AND expired_epoch<=18446744073709551615),
 FOREIGN KEY(conversion_id,reservation_id) REFERENCES issuer_btc_conversion_output_uses(intent_id,operation_id),
 UNIQUE(conversion_id,epoch,program,pool),
 CHECK((state=0 AND receipt IS NULL AND expired_epoch IS NULL)
    OR(state=1 AND receipt IS NOT NULL AND expired_epoch IS NULL)
    OR(state=2 AND receipt IS NULL AND expired_epoch IS NOT NULL))
);
CREATE UNIQUE INDEX issuer_btc_witness_funding_active ON issuer_btc_witness_funding(conversion_id) WHERE state IN(0,1);
CREATE FUNCTION issuer_btc_witness_funding_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents c JOIN issuer_btc_conversion_outputs o USING(intent_id)
  JOIN issuer_btc_conversion_output_uses u USING(intent_id)
  WHERE c.intent_id=NEW.conversion_id AND c.bucket=0 AND c.stage='output-reserved'
    AND u.bucket=0 AND NOT u.released AND u.operation_id=NEW.reservation_id
    AND u.receipt_hash=NEW.receipt_hash AND NEW.receipt_hash=sha256(o.receipt)) THEN
  RAISE EXCEPTION 'btc_witness_output_binding';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_witness_funding_binding BEFORE INSERT ON issuer_btc_witness_funding FOR EACH ROW EXECUTE FUNCTION issuer_btc_witness_funding_binding();
CREATE FUNCTION issuer_btc_witness_funding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'UPDATE' OR OLD.state<>0 OR NEW.state NOT IN(1,2)
   OR (to_jsonb(OLD)-ARRAY['state','receipt','expired_epoch'])<>(to_jsonb(NEW)-ARRAY['state','receipt','expired_epoch']) THEN
  RAISE EXCEPTION 'immutable_btc_witness_funding';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_btc_witness_funding_immutable BEFORE UPDATE OR DELETE ON issuer_btc_witness_funding FOR EACH ROW EXECUTE FUNCTION issuer_btc_witness_funding_immutable();
