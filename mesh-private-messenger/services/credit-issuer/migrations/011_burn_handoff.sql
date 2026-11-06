-- One external-owner funding schedule can contain several exact burn liabilities.
-- Its permanent funding identity is unique on the intent, not each member row.
ALTER TABLE issuer_treasury_burn_liabilities DROP CONSTRAINT issuer_treasury_burn_liabilities_funding_hash_key;
CREATE TABLE issuer_treasury_burn_intents (
 intent_id BYTEA PRIMARY KEY CHECK(octet_length(intent_id)=32),
 config_hash BYTEA NOT NULL CHECK(octet_length(config_hash)=32),
 token_program BYTEA NOT NULL CHECK(octet_length(token_program)=32),
 payer BYTEA NOT NULL CHECK(octet_length(payer)=32),
 profile BYTEA NOT NULL CHECK(octet_length(profile)=320),
 epoch NUMERIC(20,0) NOT NULL CHECK(epoch>=0 AND epoch<=18446744073709551615),
 cash NUMERIC(20,0) NOT NULL CHECK(cash>0 AND cash<=18446744073709551615),
 carry NUMERIC(20,0) NOT NULL CHECK(carry>=0 AND carry<=18446744073709551615),
 instruction BYTEA NOT NULL CHECK(octet_length(instruction)=313 AND get_byte(instruction,0)=14),
 membership_hash BYTEA NOT NULL CHECK(octet_length(membership_hash)=32),
 funding_hash BYTEA NOT NULL UNIQUE CHECK(octet_length(funding_hash)=32),
 state SMALLINT NOT NULL DEFAULT 0 CHECK(state IN(0,1)),
 finalized_slot NUMERIC(20,0) CHECK(finalized_slot>0 AND finalized_slot<=18446744073709551615),
 week_frame BYTEA CHECK(octet_length(week_frame)=2240),
 close_receipt BYTEA CHECK(octet_length(close_receipt)=256),
 UNIQUE(token_program,epoch),
 CHECK(cash+carry>=24 AND cash+carry<=18446744073709551615),
 CHECK((state=0 AND finalized_slot IS NULL AND week_frame IS NULL AND close_receipt IS NULL)
    OR (state=1 AND finalized_slot IS NOT NULL AND week_frame IS NOT NULL))
);
CREATE TABLE issuer_treasury_burn_members (
 batch_id BIGINT PRIMARY KEY REFERENCES issuer_treasury_burn_liabilities(batch_id),
 intent_id BYTEA NOT NULL REFERENCES issuer_treasury_burn_intents(intent_id)
);
CREATE FUNCTION issuer_burn_liability_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_treasury_weekly b WHERE b.batch_id=NEW.batch_id
    AND b.policy_version=2 AND b.burn=NEW.amount) THEN
   RAISE EXCEPTION 'invalid_credit_burn_liability';
 END IF;
 IF TG_OP='UPDATE' AND (OLD.batch_id<>NEW.batch_id OR OLD.amount<>NEW.amount OR OLD.state=1) THEN
   RAISE EXCEPTION 'immutable_credit_burn_liability';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_burn_liability_binding BEFORE INSERT OR UPDATE ON issuer_treasury_burn_liabilities
 FOR EACH ROW EXECUTE FUNCTION issuer_burn_liability_binding();
CREATE FUNCTION issuer_burn_member_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_liabilities l JOIN issuer_treasury_weekly b USING(batch_id)
   JOIN issuer_treasury_burn_intents i ON i.intent_id=NEW.intent_id AND i.state=0 AND i.config_hash=b.config_hash
   WHERE l.batch_id=NEW.batch_id AND l.state=0 AND b.policy_version=2 AND b.asset=0
   AND b.mint=substring(i.profile from 37 for 32)) THEN
   RAISE EXCEPTION 'invalid_credit_burn_member';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_burn_member_binding BEFORE INSERT ON issuer_treasury_burn_members
 FOR EACH ROW EXECUTE FUNCTION issuer_burn_member_binding();
CREATE FUNCTION issuer_burn_intent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state<>0 OR NEW.state<>1 OR
   (to_jsonb(OLD)-ARRAY['state','finalized_slot','week_frame','close_receipt'])<>
   (to_jsonb(NEW)-ARRAY['state','finalized_slot','week_frame','close_receipt']) THEN
   RAISE EXCEPTION 'immutable_credit_burn_intent';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_burn_intent_immutable BEFORE UPDATE ON issuer_treasury_burn_intents
 FOR EACH ROW EXECUTE FUNCTION issuer_burn_intent_immutable();

CREATE FUNCTION issuer_burn_member_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable_credit_burn_membership'; END;
$$;
CREATE TRIGGER issuer_burn_member_immutable BEFORE UPDATE OR DELETE ON issuer_treasury_burn_members
 FOR EACH ROW EXECUTE FUNCTION issuer_burn_member_immutable();
