-- Original weekly SOL allocations/carries are immutable and remain in lamports.
-- Only exact successful execution receipts create separate USDC custody rows.
CREATE TABLE issuer_sol_conversions (
 intent_id BYTEA PRIMARY KEY CHECK(octet_length(intent_id)=32),
 batch_id BIGINT NOT NULL REFERENCES issuer_treasury_weekly(batch_id),
 bucket SMALLINT NOT NULL CHECK(bucket IN(0,1)),
 profile_hash BYTEA NOT NULL CHECK(octet_length(profile_hash)=32),
 lamports NUMERIC(20,0) NOT NULL CHECK(lamports>0 AND lamports<=18446744073709551615),
 UNIQUE(batch_id,bucket)
);
CREATE TABLE issuer_sol_conversion_attempts (
 intent_id BYTEA NOT NULL REFERENCES issuer_sol_conversions(intent_id),
 ordinal SMALLINT NOT NULL CHECK(ordinal BETWEEN 0 AND 63),
 bank_hash BYTEA NOT NULL CHECK(octet_length(bank_hash)=32),
 prepared_slot NUMERIC(20,0) NOT NULL CHECK(prepared_slot>0),
 prepared_at NUMERIC(20,0) NOT NULL CHECK(prepared_at>0),
 price NUMERIC(20,0) NOT NULL CHECK(price>0),
 price_at NUMERIC(20,0) NOT NULL CHECK(price_at<=prepared_at),
 minimum NUMERIC(20,0) NOT NULL CHECK(minimum>0 AND minimum<=18446744073709551615),
 blockhash BYTEA NOT NULL CHECK(octet_length(blockhash)=32),
 last_height NUMERIC(20,0) NOT NULL CHECK(last_height>0),
 message BYTEA NOT NULL CHECK(octet_length(message) BETWEEN 1 AND 1103),
 packet BYTEA CHECK(octet_length(packet) BETWEEN 129 AND 1232),
 signature BYTEA UNIQUE CHECK(octet_length(signature)=64),
 state SMALLINT NOT NULL DEFAULT 0 CHECK(state IN(0,1,2,3,4)),
 receipt BYTEA CHECK(octet_length(receipt)=197),
 PRIMARY KEY(intent_id,ordinal),
 CHECK((state IN(0,4) AND packet IS NULL AND signature IS NULL AND receipt IS NULL)
    OR(state=1 AND packet IS NOT NULL AND signature IS NOT NULL AND receipt IS NULL)
    OR(state IN(2,3) AND packet IS NOT NULL AND signature IS NOT NULL AND receipt IS NOT NULL))
);
CREATE TABLE issuer_sol_conversion_outputs (
 intent_id BYTEA PRIMARY KEY REFERENCES issuer_sol_conversions(intent_id),
 ordinal SMALLINT NOT NULL,
 mint BYTEA NOT NULL CHECK(octet_length(mint)=32),
 owner BYTEA NOT NULL CHECK(octet_length(owner)=32),
 custody BYTEA NOT NULL CHECK(octet_length(custody)=32),
 amount NUMERIC(20,0) NOT NULL CHECK(amount>0 AND amount<=18446744073709551615),
 receipt BYTEA NOT NULL UNIQUE CHECK(octet_length(receipt)=197),
 FOREIGN KEY(intent_id,ordinal) REFERENCES issuer_sol_conversion_attempts(intent_id,ordinal)
);

-- Output-backed witness funding has its own ID and permanent receipt. It never
-- retags or overwrites a lamport allocation as if it had been USDC revenue.
CREATE TABLE issuer_sol_witness_funding (
 funding_id BYTEA PRIMARY KEY CHECK(octet_length(funding_id)=32),
 conversion_id BYTEA NOT NULL REFERENCES issuer_sol_conversion_outputs(intent_id),
 epoch NUMERIC(20,0) NOT NULL CHECK(epoch>=0 AND epoch<=18446744073709551615),
 pool BYTEA NOT NULL CHECK(octet_length(pool)=32),
 state SMALLINT NOT NULL DEFAULT 0 CHECK(state IN(0,1,2)),
 receipt BYTEA CHECK(octet_length(receipt)=192),
 UNIQUE(conversion_id,epoch),
 CHECK((state=1 AND receipt IS NOT NULL) OR(state IN(0,2) AND receipt IS NULL))
);
CREATE UNIQUE INDEX issuer_sol_witness_active ON issuer_sol_witness_funding(conversion_id) WHERE state IN(0,1);
ALTER TABLE issuer_treasury_burn_members ADD COLUMN conversion_id BYTEA REFERENCES issuer_sol_conversion_outputs(intent_id);
CREATE UNIQUE INDEX issuer_sol_burn_member_active ON issuer_treasury_burn_members(conversion_id) WHERE NOT released AND conversion_id IS NOT NULL;

-- Preserve the original USDC branch. A SOL source can join only through its
-- exact successful conversion receipt; lamports are never a USDC member amount.
CREATE OR REPLACE FUNCTION issuer_burn_member_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.released OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_liabilities l
   JOIN issuer_treasury_weekly b USING(batch_id)
   JOIN issuer_treasury_burn_intents i ON i.intent_id=NEW.intent_id AND i.state=0 AND i.config_hash=b.config_hash
   LEFT JOIN issuer_sol_conversions c ON c.intent_id=NEW.conversion_id AND c.batch_id=b.batch_id AND c.bucket=1
   LEFT JOIN issuer_sol_conversion_outputs o ON o.intent_id=c.intent_id
   LEFT JOIN issuer_sol_conversion_attempts a ON a.intent_id=o.intent_id AND a.ordinal=o.ordinal
   WHERE l.batch_id=NEW.batch_id AND l.state=0 AND l.amount=b.burn AND b.policy_version=2
   AND ((b.asset=0 AND NEW.conversion_id IS NULL AND b.mint=substring(i.profile from 37 for 32))
    OR(b.asset=1 AND b.mint=decode(repeat('00',32),'hex') AND c.lamports=l.amount
      AND a.state=2 AND a.receipt=o.receipt
      AND substring(o.receipt from 5 for 32)=c.intent_id
      AND substring(o.receipt from 37 for 32)=c.profile_hash
      AND o.mint=substring(i.profile from 37 for 32)
      AND o.owner=substring(i.profile from 69 for 32)))) THEN
   RAISE EXCEPTION 'invalid_credit_burn_member';
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION issuer_burn_member_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'immutable_credit_burn_membership'; END IF;
 IF OLD.released OR NOT NEW.released OR OLD.intent_id<>NEW.intent_id OR OLD.batch_id<>NEW.batch_id
   OR NEW.conversion_id IS DISTINCT FROM OLD.conversion_id
   OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_intents i WHERE i.intent_id=OLD.intent_id AND i.state=2) THEN
   RAISE EXCEPTION 'immutable_credit_burn_membership';
 END IF;
 RETURN NEW;
END;
$$;
