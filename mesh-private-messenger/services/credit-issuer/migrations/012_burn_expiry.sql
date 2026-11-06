-- Additive permanent unfunded-week recovery. Existing funded bytes stay intact.
ALTER TABLE issuer_treasury_burn_intents
 DROP CONSTRAINT issuer_treasury_burn_intents_state_check,
 DROP CONSTRAINT issuer_treasury_burn_intents_check1,
 ADD COLUMN expiry_slot NUMERIC(20,0) CHECK(expiry_slot>0 AND expiry_slot<=18446744073709551615),
 ADD COLUMN expiry_frame BYTEA CHECK(octet_length(expiry_frame)=192),
 ADD COLUMN expiry_receipt BYTEA CHECK(octet_length(expiry_receipt)=256),
 ADD CONSTRAINT issuer_burn_intent_state CHECK(state IN(0,1,2)),
 ADD CONSTRAINT issuer_burn_intent_terminal CHECK(
  (state=0 AND finalized_slot IS NULL AND week_frame IS NULL AND close_receipt IS NULL
    AND expiry_slot IS NULL AND expiry_frame IS NULL AND expiry_receipt IS NULL)
  OR (state=1 AND finalized_slot IS NOT NULL AND week_frame IS NOT NULL
    AND expiry_slot IS NULL AND expiry_frame IS NULL AND expiry_receipt IS NULL)
  OR (state=2 AND finalized_slot IS NULL AND week_frame IS NULL AND close_receipt IS NULL
    AND expiry_slot IS NOT NULL AND expiry_frame IS NOT NULL AND expiry_receipt IS NOT NULL));

ALTER TABLE issuer_treasury_burn_members
 ADD COLUMN released BOOLEAN NOT NULL DEFAULT false,
 DROP CONSTRAINT issuer_treasury_burn_members_pkey,
 ADD PRIMARY KEY(intent_id,batch_id);
CREATE UNIQUE INDEX issuer_burn_active_member ON issuer_treasury_burn_members(batch_id) WHERE NOT released;

CREATE OR REPLACE FUNCTION issuer_burn_intent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state<>0 OR NEW.state NOT IN(1,2) OR
   (to_jsonb(OLD)-ARRAY['state','finalized_slot','week_frame','close_receipt','expiry_slot','expiry_frame','expiry_receipt'])<>
   (to_jsonb(NEW)-ARRAY['state','finalized_slot','week_frame','close_receipt','expiry_slot','expiry_frame','expiry_receipt']) THEN
   RAISE EXCEPTION 'immutable_credit_burn_intent';
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION issuer_burn_member_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.released OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_liabilities l
   JOIN issuer_treasury_weekly b USING(batch_id)
   JOIN issuer_treasury_burn_intents i ON i.intent_id=NEW.intent_id AND i.state=0 AND i.config_hash=b.config_hash
   WHERE l.batch_id=NEW.batch_id AND l.state=0 AND b.policy_version=2 AND b.asset=0
   AND b.mint=substring(i.profile from 37 for 32)) THEN
   RAISE EXCEPTION 'invalid_credit_burn_member';
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION issuer_burn_member_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'immutable_credit_burn_membership'; END IF;
 IF OLD.released OR NOT NEW.released OR OLD.intent_id<>NEW.intent_id OR OLD.batch_id<>NEW.batch_id
   OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_intents i WHERE i.intent_id=OLD.intent_id AND i.state=2) THEN
   RAISE EXCEPTION 'immutable_credit_burn_membership';
 END IF;
 RETURN NEW;
END;
$$;
