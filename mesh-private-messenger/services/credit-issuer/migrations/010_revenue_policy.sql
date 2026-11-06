-- A quote pins its revenue policy before payment; activation never rewrites history.
CREATE TABLE issuer_revenue_policies (
  policy_version SMALLINT PRIMARY KEY CHECK(policy_version IN(1,2)),
  policy_hash BYTEA NOT NULL CHECK(octet_length(policy_hash)=32),
  UNIQUE(policy_version,policy_hash)
);
INSERT INTO issuer_revenue_policies VALUES
 (1,sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5','UTF8'))),
 (2,sha256(convert_to('morse-credit-revenue-split-v2:gross=2/10,3/10,5/10;carry=per-share-numerator;reserve=sum-carry/10','UTF8')));
CREATE FUNCTION issuer_revenue_policy_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME='issuer_revenue_policies' THEN
    RAISE EXCEPTION 'immutable_credit_revenue_policy';
  END IF;
  IF TG_TABLE_NAME IN('issuer_credit_revenue','issuer_lightning_revenue','issuer_treasury_weekly','issuer_lightning_weekly')
     AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'immutable_credit_revenue_allocation';
  END IF;
  IF OLD.policy_version<>NEW.policy_version OR OLD.policy_hash<>NEW.policy_hash THEN
    RAISE EXCEPTION 'immutable_credit_revenue_policy';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_revenue_policies_immutable BEFORE UPDATE OR DELETE ON issuer_revenue_policies
 FOR EACH ROW EXECUTE FUNCTION issuer_revenue_policy_immutable();

-- Defaults deliberately preserve the original 20/80 policy for all historical rows.
DO $$
DECLARE relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY['issuer_quotes','issuer_credit_revenue','issuer_lightning_quotes','issuer_lightning_revenue','issuer_treasury_weekly'] LOOP
    EXECUTE format('ALTER TABLE %I ADD COLUMN policy_version SMALLINT NOT NULL DEFAULT 1, ADD COLUMN policy_hash BYTEA NOT NULL DEFAULT sha256(convert_to(''morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'',''UTF8'')), ADD FOREIGN KEY(policy_version,policy_hash) REFERENCES issuer_revenue_policies(policy_version,policy_hash)',relation_name);
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION issuer_revenue_policy_immutable()',relation_name||'_policy_immutable',relation_name);
  END LOOP;
END;
$$;
CREATE FUNCTION issuer_revenue_parent_policy() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_version smallint; parent_hash bytea;
BEGIN
  IF TG_TABLE_NAME='issuer_credit_revenue' THEN
    SELECT policy_version,policy_hash INTO STRICT parent_version,parent_hash FROM issuer_quotes WHERE quote_id=NEW.quote_id;
  ELSE
    SELECT policy_version,policy_hash INTO STRICT parent_version,parent_hash FROM issuer_lightning_quotes WHERE quote_id=NEW.quote_id;
  END IF;
  IF NEW.policy_version<>parent_version OR NEW.policy_hash<>parent_hash THEN
    RAISE EXCEPTION 'credit_revenue_policy_mismatch';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_credit_revenue_parent BEFORE INSERT OR UPDATE ON issuer_credit_revenue
 FOR EACH ROW EXECUTE FUNCTION issuer_revenue_parent_policy();
CREATE TRIGGER issuer_lightning_revenue_parent BEFORE INSERT OR UPDATE ON issuer_lightning_revenue
 FOR EACH ROW EXECUTE FUNCTION issuer_revenue_parent_policy();

ALTER TABLE issuer_treasury_weekly
 DROP CONSTRAINT issuer_treasury_weekly_carry_before_check,
 DROP CONSTRAINT issuer_treasury_weekly_carry_after_check,
 DROP CONSTRAINT issuer_treasury_weekly_check,
 DROP CONSTRAINT issuer_treasury_weekly_check1,
 DROP CONSTRAINT issuer_treasury_weekly_week_asset_key,
 ADD COLUMN burn NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK(burn>=0 AND burn<=18446744073709551615),
 ADD COLUMN burn_carry_before SMALLINT NOT NULL DEFAULT 0 CHECK(burn_carry_before BETWEEN 0 AND 9),
 ADD COLUMN burn_carry_after SMALLINT NOT NULL DEFAULT 0 CHECK(burn_carry_after BETWEEN 0 AND 9),
 ADD COLUMN operations_carry_before SMALLINT NOT NULL DEFAULT 0 CHECK(operations_carry_before BETWEEN 0 AND 9),
 ADD COLUMN operations_carry_after SMALLINT NOT NULL DEFAULT 0 CHECK(operations_carry_after BETWEEN 0 AND 9),
 ADD COLUMN reserve_before SMALLINT NOT NULL DEFAULT 0 CHECK(reserve_before BETWEEN 0 AND 2),
 ADD COLUMN reserve_after SMALLINT NOT NULL DEFAULT 0 CHECK(reserve_after BETWEEN 0 AND 2),
 ADD CHECK(carry_before BETWEEN 0 AND 9 AND carry_after BETWEEN 0 AND 9),
 ADD CONSTRAINT issuer_treasury_weekly_policy_math CHECK(
  (policy_version=1 AND carry_before<=4 AND carry_after<=4 AND burn=0
   AND burn_carry_before=0 AND burn_carry_after=0 AND operations_carry_before=0 AND operations_carry_after=0
   AND reserve_before=0 AND reserve_after=0 AND witness+operations=amount
   AND witness*5+carry_after=amount+carry_before)
  OR
  (policy_version=2 AND witness*10+carry_after=amount*2+carry_before
   AND burn*10+burn_carry_after=amount*3+burn_carry_before
   AND operations*10+operations_carry_after=amount*5+operations_carry_before
   AND carry_before+burn_carry_before+operations_carry_before=reserve_before*10
   AND carry_after+burn_carry_after+operations_carry_after=reserve_after*10
   AND witness+burn+operations+reserve_after=amount+reserve_before)),
 ADD UNIQUE(week,asset,policy_version);

CREATE FUNCTION issuer_weekly_member_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_credit_revenue e JOIN issuer_treasury_weekly b
    ON b.batch_id=NEW.batch_id AND b.policy_version=e.policy_version AND b.policy_hash=e.policy_hash
    AND b.asset=e.asset AND b.mint=e.mint WHERE e.event_id=NEW.event_id) THEN
   RAISE EXCEPTION 'credit_week_member_policy_mismatch';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_weekly_member_policy BEFORE INSERT OR UPDATE ON issuer_treasury_weekly_events
 FOR EACH ROW EXECUTE FUNCTION issuer_weekly_member_policy();

-- Burn is a liability, not operations or a presumed swap. Exact external custody
-- handoff is separately reconciled; disabling the operator never releases it.
CREATE TABLE issuer_treasury_burn_liabilities (
 batch_id BIGINT PRIMARY KEY REFERENCES issuer_treasury_weekly(batch_id),
 amount NUMERIC(20,0) NOT NULL CHECK(amount>0 AND amount<=18446744073709551615),
 state SMALLINT NOT NULL DEFAULT 0 CHECK(state IN(0,1)),
 funding_hash BYTEA UNIQUE CHECK(octet_length(funding_hash)=32),
 receipt BYTEA,
 CHECK((state=0 AND funding_hash IS NULL AND receipt IS NULL) OR
       (state=1 AND funding_hash IS NOT NULL AND receipt IS NOT NULL))
);

-- Lightning holds BTC at its pinned node, not a Solana treasury account. Keep
-- its exact millisatoshi allocations in an independent conversion-pending lane.
CREATE TABLE issuer_lightning_weekly (
 batch_id BIGSERIAL PRIMARY KEY,
 week NUMERIC(20,0) NOT NULL CHECK(week>=0 AND week<=18446744073709551615),
 backend_hash BYTEA NOT NULL CHECK(octet_length(backend_hash)=32),
 policy_version SMALLINT NOT NULL,
 policy_hash BYTEA NOT NULL,
 amount NUMERIC(20,0) NOT NULL CHECK(amount>=0 AND amount<=18446744073709551615),
 witness NUMERIC(20,0) NOT NULL CHECK(witness>=0),
 burn NUMERIC(20,0) NOT NULL CHECK(burn>=0),
 operations NUMERIC(20,0) NOT NULL CHECK(operations>=0),
 carry_before SMALLINT NOT NULL CHECK(carry_before BETWEEN 0 AND 9),
 carry_after SMALLINT NOT NULL CHECK(carry_after BETWEEN 0 AND 9),
 burn_carry_before SMALLINT NOT NULL CHECK(burn_carry_before BETWEEN 0 AND 9),
 burn_carry_after SMALLINT NOT NULL CHECK(burn_carry_after BETWEEN 0 AND 9),
 operations_carry_before SMALLINT NOT NULL CHECK(operations_carry_before BETWEEN 0 AND 9),
 operations_carry_after SMALLINT NOT NULL CHECK(operations_carry_after BETWEEN 0 AND 9),
 reserve_before SMALLINT NOT NULL CHECK(reserve_before BETWEEN 0 AND 2),
 reserve_after SMALLINT NOT NULL CHECK(reserve_after BETWEEN 0 AND 2),
 membership_hash BYTEA NOT NULL CHECK(octet_length(membership_hash)=32),
 FOREIGN KEY(policy_version,policy_hash) REFERENCES issuer_revenue_policies(policy_version,policy_hash),
 UNIQUE(backend_hash,week,policy_version),
 CHECK((policy_version=1 AND carry_before<=4 AND carry_after<=4 AND burn=0
   AND burn_carry_before=0 AND burn_carry_after=0 AND operations_carry_before=0 AND operations_carry_after=0
   AND reserve_before=0 AND reserve_after=0 AND witness+operations=amount
   AND witness*5+carry_after=amount+carry_before)
  OR (policy_version=2 AND witness*10+carry_after=amount*2+carry_before
   AND burn*10+burn_carry_after=amount*3+burn_carry_before
   AND operations*10+operations_carry_after=amount*5+operations_carry_before
   AND carry_before+burn_carry_before+operations_carry_before=reserve_before*10
   AND carry_after+burn_carry_after+operations_carry_after=reserve_after*10
   AND witness+burn+operations+reserve_after=amount+reserve_before))
);
CREATE TRIGGER issuer_lightning_weekly_policy_immutable BEFORE UPDATE ON issuer_lightning_weekly
 FOR EACH ROW EXECUTE FUNCTION issuer_revenue_policy_immutable();
CREATE TABLE issuer_lightning_weekly_events (
 quote_id BYTEA PRIMARY KEY REFERENCES issuer_lightning_revenue(quote_id),
 batch_id BIGINT NOT NULL REFERENCES issuer_lightning_weekly(batch_id)
);
CREATE FUNCTION issuer_lightning_week_member_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_lightning_revenue e JOIN issuer_lightning_weekly b
    ON b.batch_id=NEW.batch_id AND b.policy_version=e.policy_version AND b.policy_hash=e.policy_hash
    AND b.backend_hash=e.backend_hash WHERE e.quote_id=NEW.quote_id) THEN
   RAISE EXCEPTION 'lightning_week_member_policy_mismatch';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER issuer_lightning_week_member_policy BEFORE INSERT OR UPDATE ON issuer_lightning_weekly_events
 FOR EACH ROW EXECUTE FUNCTION issuer_lightning_week_member_policy();
