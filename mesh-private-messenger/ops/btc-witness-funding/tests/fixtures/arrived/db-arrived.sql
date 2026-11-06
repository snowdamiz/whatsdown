--
-- PostgreSQL database dump
--

\restrict MgsbpzUZ6c09PdfJUcMqtL6eT9icYi8o2yI9eB5bqTv3Ew1yBHKNbdUdMypg3mh

-- Dumped from database version 17.11 (Homebrew)
-- Dumped by pg_dump version 17.11 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: andreyyurlov
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO andreyyurlov;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: andreyyurlov
--

COMMENT ON SCHEMA public IS '';


--
-- Name: issuer_btc_accounting_binding(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_accounting_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i WHERE i.intent_id=NEW.intent_id AND i.stage IN('order-unknown','order-known')
  AND NEW.actual_routing_fee_msat<=i.routing_fee_limit_msat AND NEW.actual_btc_fee_msat<=i.provider_btc_reserve_msat
  AND NEW.lnd_residual_msat=i.routing_fee_limit_msat-NEW.actual_routing_fee_msat+i.dust_msat
  AND NEW.provider_btc_residual_msat=i.provider_btc_reserve_msat-NEW.actual_btc_fee_msat
  AND i.source_msat=i.trade_sats*1000+NEW.actual_btc_fee_msat+NEW.actual_routing_fee_msat+NEW.lnd_residual_msat+NEW.provider_btc_residual_msat) THEN RAISE EXCEPTION 'btc_actual_accounting_mismatch'; END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_btc_accounting_binding() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_artifact_immutable(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_artifact_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN RAISE EXCEPTION 'immutable_btc_conversion_artifact'; END;
$$;


ALTER FUNCTION public.issuer_btc_artifact_immutable() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_source(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_conversion_source() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_btc_conversion_source() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_transition(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_conversion_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_btc_conversion_transition() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_draft_admission(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_draft_admission() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i WHERE i.intent_id=NEW.intent_id AND NEW.revision=i.revision+1 AND
  ((NEW.kind='order' AND i.stage IN('delivered','order-ready')) OR (NEW.kind='withdrawal' AND i.stage IN('converted','withdrawal-ready')))) THEN RAISE EXCEPTION 'btc_draft_not_refreshable'; END IF;
 IF (SELECT COUNT(*) FROM issuer_btc_conversion_drafts d WHERE d.intent_id=NEW.intent_id AND d.kind=NEW.kind)>=32 THEN RAISE EXCEPTION 'btc_draft_capacity'; END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_btc_draft_admission() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_output_admission(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_output_admission() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_btc_output_admission() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_output_release(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_output_release() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP<>'UPDATE' OR OLD.released OR NOT NEW.released OR OLD.bucket<>1
   OR (to_jsonb(OLD)-ARRAY['released','expiry_receipt','burn_intent_id'])<>(to_jsonb(NEW)-ARRAY['released','expiry_receipt','burn_intent_id'])
   OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_intents b WHERE b.intent_id=OLD.operation_id
     AND b.state=2 AND b.expiry_receipt=NEW.expiry_receipt) THEN RAISE EXCEPTION 'btc_output_release_not_proven_unfunded'; END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_btc_output_release() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_output_use_binding(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_output_use_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_intents i JOIN issuer_btc_conversion_outputs o USING(intent_id)
   WHERE i.intent_id=NEW.intent_id AND i.bucket=NEW.bucket AND i.stage='arrived' AND NOT NEW.released
   AND NEW.receipt_hash=sha256(o.receipt) AND (NEW.bucket=0 OR EXISTS(SELECT 1 FROM issuer_treasury_burn_intents b WHERE b.intent_id=NEW.operation_id AND b.state=0 AND b.config_hash=i.treasury_config_hash AND b.payer=o.owner AND substring(b.profile from 37 for 32)=o.mint))) THEN RAISE EXCEPTION 'btc_output_use_mismatch'; END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_btc_output_use_binding() OWNER TO andreyyurlov;

--
-- Name: issuer_btc_request_capacity(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_btc_request_capacity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (SELECT COUNT(*) FROM issuer_btc_conversion_requests r WHERE r.intent_id=NEW.intent_id)>=256 THEN RAISE EXCEPTION 'btc_request_capacity'; END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_btc_request_capacity() OWNER TO andreyyurlov;

--
-- Name: issuer_burn_intent_immutable(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_burn_intent_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF OLD.state<>0 OR NEW.state NOT IN(1,2) OR
   (to_jsonb(OLD)-ARRAY['state','finalized_slot','week_frame','close_receipt','expiry_slot','expiry_frame','expiry_receipt'])<>
   (to_jsonb(NEW)-ARRAY['state','finalized_slot','week_frame','close_receipt','expiry_slot','expiry_frame','expiry_receipt']) THEN
   RAISE EXCEPTION 'immutable_credit_burn_intent';
 END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_burn_intent_immutable() OWNER TO andreyyurlov;

--
-- Name: issuer_burn_liability_binding(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_burn_liability_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_burn_liability_binding() OWNER TO andreyyurlov;

--
-- Name: issuer_burn_member_binding(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_burn_member_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_burn_member_binding() OWNER TO andreyyurlov;

--
-- Name: issuer_burn_member_immutable(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_burn_member_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'immutable_credit_burn_membership'; END IF;
 IF OLD.released OR NOT NEW.released OR OLD.intent_id<>NEW.intent_id OR OLD.batch_id<>NEW.batch_id
   OR NOT EXISTS(SELECT 1 FROM issuer_treasury_burn_intents i WHERE i.intent_id=OLD.intent_id AND i.state=2) THEN
   RAISE EXCEPTION 'immutable_credit_burn_membership';
 END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_burn_member_immutable() OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_week_member_policy(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_lightning_week_member_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_lightning_revenue e JOIN issuer_lightning_weekly b
    ON b.batch_id=NEW.batch_id AND b.policy_version=e.policy_version AND b.policy_hash=e.policy_hash
    AND b.backend_hash=e.backend_hash WHERE e.quote_id=NEW.quote_id) THEN
   RAISE EXCEPTION 'lightning_week_member_policy_mismatch';
 END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_lightning_week_member_policy() OWNER TO andreyyurlov;

--
-- Name: issuer_revenue_parent_policy(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_revenue_parent_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_revenue_parent_policy() OWNER TO andreyyurlov;

--
-- Name: issuer_revenue_policy_immutable(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_revenue_policy_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


ALTER FUNCTION public.issuer_revenue_policy_immutable() OWNER TO andreyyurlov;

--
-- Name: issuer_weekly_member_policy(); Type: FUNCTION; Schema: public; Owner: andreyyurlov
--

CREATE FUNCTION public.issuer_weekly_member_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuer_credit_revenue e JOIN issuer_treasury_weekly b
    ON b.batch_id=NEW.batch_id AND b.policy_version=e.policy_version AND b.policy_hash=e.policy_hash
    AND b.asset=e.asset AND b.mint=e.mint WHERE e.event_id=NEW.event_id) THEN
   RAISE EXCEPTION 'credit_week_member_policy_mismatch';
 END IF;
 RETURN NEW;
END;
$$;


ALTER FUNCTION public.issuer_weekly_member_policy() OWNER TO andreyyurlov;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: issuer_btc_conversion_accounting; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_accounting (
    intent_id bytea NOT NULL,
    actual_routing_fee_msat numeric(20,0) NOT NULL,
    actual_btc_fee_msat numeric(20,0) NOT NULL,
    actual_usdc_fee_100ths numeric(20,0) NOT NULL,
    lnd_residual_msat numeric(20,0) NOT NULL,
    provider_btc_residual_msat numeric(20,0) NOT NULL,
    provider_usdc_residual_100ths smallint NOT NULL,
    provider_net_usdc numeric(20,0) NOT NULL,
    CONSTRAINT issuer_btc_conversion_accoun_provider_usdc_residual_100th_check CHECK (((provider_usdc_residual_100ths >= 0) AND (provider_usdc_residual_100ths <= 99))),
    CONSTRAINT issuer_btc_conversion_accounti_provider_btc_residual_msat_check CHECK ((provider_btc_residual_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_accounting_actual_btc_fee_msat_check CHECK ((actual_btc_fee_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_accounting_actual_routing_fee_msat_check CHECK ((actual_routing_fee_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_accounting_actual_usdc_fee_100ths_check CHECK ((actual_usdc_fee_100ths >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_accounting_lnd_residual_msat_check CHECK ((lnd_residual_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_accounting_provider_net_usdc_check CHECK (((provider_net_usdc > (0)::numeric) AND (provider_net_usdc <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_btc_conversion_accounting OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_artifacts; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_artifacts (
    intent_id bytea NOT NULL,
    kind text NOT NULL,
    body text NOT NULL,
    body_sha256 bytea NOT NULL,
    CONSTRAINT issuer_btc_conversion_artifacts_body_check CHECK (((octet_length(body) >= 1) AND (octet_length(body) <= 262144))),
    CONSTRAINT issuer_btc_conversion_artifacts_body_sha256_check CHECK ((octet_length(body_sha256) = 32)),
    CONSTRAINT issuer_btc_conversion_artifacts_check CHECK ((body_sha256 = sha256(convert_to(body, 'UTF8'::name)))),
    CONSTRAINT issuer_btc_conversion_artifacts_kind_check CHECK (((length(kind) >= 1) AND (length(kind) <= 96)))
);


ALTER TABLE public.issuer_btc_conversion_artifacts OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_deferrals; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_deferrals (
    batch_id bigint NOT NULL,
    bucket smallint NOT NULL,
    profile_hash bytea NOT NULL,
    reason text NOT NULL,
    observed_at numeric(20,0) NOT NULL,
    CONSTRAINT issuer_btc_conversion_deferrals_bucket_check CHECK ((bucket = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_btc_conversion_deferrals_observed_at_check CHECK ((observed_at > (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_deferrals_profile_hash_check CHECK ((octet_length(profile_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_deferrals_reason_check CHECK ((reason = ANY (ARRAY['below-minimum-order'::text, 'full-fee-floor-unavailable'::text, 'source-limit'::text])))
);


ALTER TABLE public.issuer_btc_conversion_deferrals OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_drafts; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_drafts (
    intent_id bytea NOT NULL,
    kind text NOT NULL,
    revision bigint NOT NULL,
    observed_at numeric(20,0) NOT NULL,
    body text NOT NULL,
    body_sha256 bytea NOT NULL,
    CONSTRAINT issuer_btc_conversion_drafts_body_check CHECK (((octet_length(body) >= 1) AND (octet_length(body) <= 16384))),
    CONSTRAINT issuer_btc_conversion_drafts_check CHECK (((octet_length(body_sha256) = 32) AND (body_sha256 = sha256(convert_to(body, 'UTF8'::name))))),
    CONSTRAINT issuer_btc_conversion_drafts_kind_check CHECK ((kind = ANY (ARRAY['order'::text, 'withdrawal'::text]))),
    CONSTRAINT issuer_btc_conversion_drafts_observed_at_check CHECK ((observed_at > (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_drafts_revision_check CHECK ((revision > 0))
);


ALTER TABLE public.issuer_btc_conversion_drafts OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_intents; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_intents (
    intent_id bytea NOT NULL,
    batch_id bigint NOT NULL,
    bucket smallint NOT NULL,
    profile_hash bytea NOT NULL,
    treasury_config_hash bytea NOT NULL,
    policy_version smallint NOT NULL,
    policy_hash bytea NOT NULL,
    membership_hash bytea NOT NULL,
    backend_hash bytea NOT NULL,
    source_msat numeric(20,0) NOT NULL,
    invoice_msat numeric(20,0) NOT NULL,
    trade_sats numeric(20,0) NOT NULL,
    provider_btc_reserve_msat numeric(20,0) NOT NULL,
    routing_fee_limit_msat numeric(20,0) NOT NULL,
    dust_msat smallint NOT NULL,
    minimum_output_usdc numeric(20,0) NOT NULL,
    minimum_gross_usdc numeric(20,0) NOT NULL,
    limit_price_micros numeric(20,0) NOT NULL,
    reference_price_micros numeric(20,0) NOT NULL,
    reference_at numeric(20,0) NOT NULL,
    reserved_at numeric(20,0) NOT NULL,
    stage text DEFAULT 'reserved'::text NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    order_draft_revision bigint,
    withdrawal_draft_revision bigint,
    order_draft_kind text GENERATED ALWAYS AS ('order'::text) STORED,
    withdrawal_draft_kind text GENERATED ALWAYS AS ('withdrawal'::text) STORED,
    invoice_hash bytea,
    order_id text,
    withdrawal_id text,
    provider_credit_status text DEFAULT 'not-independently-proven'::text NOT NULL,
    CONSTRAINT issuer_btc_conversion_intents_backend_hash_check CHECK ((octet_length(backend_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_bucket_check CHECK ((bucket = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_btc_conversion_intents_check CHECK (((minimum_gross_usdc >= minimum_output_usdc) AND (minimum_gross_usdc <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_check1 CHECK (((reference_price_micros >= limit_price_micros) AND (reference_price_micros <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_check2 CHECK (((reserved_at >= reference_at) AND ((reserved_at - reference_at) <= (60)::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_check3 CHECK ((source_msat = ((invoice_msat + routing_fee_limit_msat) + (dust_msat)::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_check4 CHECK ((((trade_sats * (1000)::numeric) + provider_btc_reserve_msat) = invoice_msat)),
    CONSTRAINT issuer_btc_conversion_intents_dust_msat_check CHECK (((dust_msat >= 0) AND (dust_msat <= 999))),
    CONSTRAINT issuer_btc_conversion_intents_intent_id_check CHECK ((octet_length(intent_id) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_invoice_hash_check CHECK ((octet_length(invoice_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_invoice_msat_check CHECK (((invoice_msat > (0)::numeric) AND (mod(invoice_msat, (1000)::numeric) = (0)::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_limit_price_micros_check CHECK (((limit_price_micros > (0)::numeric) AND (limit_price_micros <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_membership_hash_check CHECK ((octet_length(membership_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_minimum_output_usdc_check CHECK (((minimum_output_usdc > (0)::numeric) AND (minimum_output_usdc <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_order_id_check CHECK (((length(order_id) >= 1) AND (length(order_id) <= 64))),
    CONSTRAINT issuer_btc_conversion_intents_policy_hash_check CHECK ((octet_length(policy_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_profile_hash_check CHECK ((octet_length(profile_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_provider_btc_reserve_msat_check CHECK ((provider_btc_reserve_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_intents_provider_credit_status_check CHECK ((provider_credit_status = 'not-independently-proven'::text)),
    CONSTRAINT issuer_btc_conversion_intents_reference_at_check CHECK ((reference_at > (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_intents_revision_check CHECK ((revision >= 0)),
    CONSTRAINT issuer_btc_conversion_intents_routing_fee_limit_msat_check CHECK ((routing_fee_limit_msat >= (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_intents_source_msat_check CHECK (((source_msat > (0)::numeric) AND (source_msat <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_intents_stage_check CHECK ((stage = ANY (ARRAY['reserved'::text, 'invoice-unknown'::text, 'invoice-ready'::text, 'payment-unknown'::text, 'delivered'::text, 'order-ready'::text, 'order-unknown'::text, 'order-known'::text, 'converted'::text, 'withdrawal-ready'::text, 'withdrawal-unknown'::text, 'withdrawal-known'::text, 'arrived'::text, 'output-reserved'::text, 'held'::text]))),
    CONSTRAINT issuer_btc_conversion_intents_trade_sats_check CHECK ((trade_sats > (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_intents_treasury_config_hash_check CHECK ((octet_length(treasury_config_hash) = 32)),
    CONSTRAINT issuer_btc_conversion_intents_withdrawal_id_check CHECK (((length(withdrawal_id) >= 1) AND (length(withdrawal_id) <= 64)))
);


ALTER TABLE public.issuer_btc_conversion_intents OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_output_uses; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_output_uses (
    intent_id bytea NOT NULL,
    bucket smallint NOT NULL,
    operation_id bytea NOT NULL,
    receipt_hash bytea NOT NULL,
    released boolean DEFAULT false NOT NULL,
    expiry_receipt bytea,
    burn_intent_id bytea GENERATED ALWAYS AS (
CASE
    WHEN (bucket = 1) THEN operation_id
    ELSE NULL::bytea
END) STORED,
    CONSTRAINT issuer_btc_conversion_output_uses_bucket_check CHECK ((bucket = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_btc_conversion_output_uses_check CHECK ((((NOT released) AND (expiry_receipt IS NULL)) OR (released AND (bucket = 1) AND (expiry_receipt IS NOT NULL)))),
    CONSTRAINT issuer_btc_conversion_output_uses_expiry_receipt_check CHECK ((octet_length(expiry_receipt) = 256)),
    CONSTRAINT issuer_btc_conversion_output_uses_operation_id_check CHECK ((octet_length(operation_id) = 32)),
    CONSTRAINT issuer_btc_conversion_output_uses_receipt_hash_check CHECK ((octet_length(receipt_hash) = 32))
);


ALTER TABLE public.issuer_btc_conversion_output_uses OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_outputs; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_outputs (
    intent_id bytea NOT NULL,
    mint bytea NOT NULL,
    owner bytea NOT NULL,
    custody bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    transaction_signature bytea NOT NULL,
    receipt bytea NOT NULL,
    CONSTRAINT issuer_btc_conversion_outputs_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_outputs_custody_check CHECK ((octet_length(custody) = 32)),
    CONSTRAINT issuer_btc_conversion_outputs_mint_check CHECK ((octet_length(mint) = 32)),
    CONSTRAINT issuer_btc_conversion_outputs_owner_check CHECK ((octet_length(owner) = 32)),
    CONSTRAINT issuer_btc_conversion_outputs_receipt_check CHECK (((octet_length(receipt) = 340) AND (SUBSTRING(receipt FROM 1 FOR 4) = decode('4d434232'::text, 'hex'::text)))),
    CONSTRAINT issuer_btc_conversion_outputs_transaction_signature_check CHECK ((octet_length(transaction_signature) = 64))
);


ALTER TABLE public.issuer_btc_conversion_outputs OWNER TO andreyyurlov;

--
-- Name: issuer_btc_conversion_requests; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_conversion_requests (
    intent_id bytea NOT NULL,
    kind text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    nonce numeric(20,0) NOT NULL,
    content_type text NOT NULL,
    body text NOT NULL,
    signature text NOT NULL,
    created_at numeric(20,0) NOT NULL,
    CONSTRAINT issuer_btc_conversion_requests_body_check CHECK ((octet_length(body) <= 16384)),
    CONSTRAINT issuer_btc_conversion_requests_content_type_check CHECK ((length(content_type) <= 128)),
    CONSTRAINT issuer_btc_conversion_requests_created_at_check CHECK ((created_at > (0)::numeric)),
    CONSTRAINT issuer_btc_conversion_requests_kind_check CHECK (((length(kind) >= 1) AND (length(kind) <= 96))),
    CONSTRAINT issuer_btc_conversion_requests_method_check CHECK ((method = ANY (ARRAY['GET'::text, 'POST'::text]))),
    CONSTRAINT issuer_btc_conversion_requests_nonce_check CHECK (((nonce >= (0)::numeric) AND (nonce <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_conversion_requests_path_check CHECK (((octet_length(path) >= 1) AND (octet_length(path) <= 4096))),
    CONSTRAINT issuer_btc_conversion_requests_signature_check CHECK ((length(signature) <= 128))
);


ALTER TABLE public.issuer_btc_conversion_requests OWNER TO andreyyurlov;

--
-- Name: issuer_btc_kraken_nonces; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_btc_kraken_nonces (
    api_key_hash bytea NOT NULL,
    value numeric(20,0) NOT NULL,
    lease_id bytea,
    lease_until numeric(20,0) DEFAULT 0 NOT NULL,
    observed_at numeric(20,0) DEFAULT 0 NOT NULL,
    CONSTRAINT issuer_btc_kraken_nonces_api_key_hash_check CHECK ((octet_length(api_key_hash) = 32)),
    CONSTRAINT issuer_btc_kraken_nonces_lease_id_check CHECK ((octet_length(lease_id) = 32)),
    CONSTRAINT issuer_btc_kraken_nonces_lease_until_check CHECK (((lease_until >= (0)::numeric) AND (lease_until <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_kraken_nonces_observed_at_check CHECK (((observed_at >= (0)::numeric) AND (observed_at <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_btc_kraken_nonces_value_check CHECK (((value >= (0)::numeric) AND (value <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_btc_kraken_nonces OWNER TO andreyyurlov;

--
-- Name: issuer_credit_revenue; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_credit_revenue (
    event_id bigint NOT NULL,
    quote_id bytea NOT NULL,
    payment_signature bytea NOT NULL,
    asset smallint NOT NULL,
    mint bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    payment_time numeric(20,0) NOT NULL,
    policy_version smallint DEFAULT 1 NOT NULL,
    policy_hash bytea DEFAULT sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'::text, 'UTF8'::name)) NOT NULL,
    CONSTRAINT issuer_credit_revenue_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_credit_revenue_asset_check CHECK ((asset = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_credit_revenue_mint_check CHECK ((octet_length(mint) = 32)),
    CONSTRAINT issuer_credit_revenue_payment_signature_check CHECK ((octet_length(payment_signature) = 64)),
    CONSTRAINT issuer_credit_revenue_payment_time_check CHECK (((payment_time >= (0)::numeric) AND (payment_time <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_credit_revenue OWNER TO andreyyurlov;

--
-- Name: issuer_credit_revenue_event_id_seq; Type: SEQUENCE; Schema: public; Owner: andreyyurlov
--

CREATE SEQUENCE public.issuer_credit_revenue_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.issuer_credit_revenue_event_id_seq OWNER TO andreyyurlov;

--
-- Name: issuer_credit_revenue_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: andreyyurlov
--

ALTER SEQUENCE public.issuer_credit_revenue_event_id_seq OWNED BY public.issuer_credit_revenue.event_id;


--
-- Name: issuer_deposit_root; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_deposit_root (
    singleton boolean NOT NULL,
    sealed_seed bytea NOT NULL,
    CONSTRAINT issuer_deposit_root_sealed_seed_check CHECK ((octet_length(sealed_seed) = 99)),
    CONSTRAINT issuer_deposit_root_singleton_check CHECK (singleton)
);


ALTER TABLE public.issuer_deposit_root OWNER TO andreyyurlov;

--
-- Name: issuer_keys; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_keys (
    key_id bytea NOT NULL,
    epoch numeric(20,0) NOT NULL,
    purpose smallint NOT NULL,
    spki bytea NOT NULL,
    sealed_private_key bytea NOT NULL,
    admitted_evidence bytea,
    quote_public_key bytea,
    sealed_quote_key bytea,
    CONSTRAINT issuer_keys_epoch_check CHECK ((epoch >= (0)::numeric)),
    CONSTRAINT issuer_keys_key_id_check CHECK ((octet_length(key_id) = 32)),
    CONSTRAINT issuer_keys_purpose_check CHECK ((purpose = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_keys_quote_public_key_check CHECK ((octet_length(quote_public_key) = 32)),
    CONSTRAINT issuer_keys_sealed_private_key_check CHECK (((octet_length(sealed_private_key) >= 68) AND (octet_length(sealed_private_key) <= 8192))),
    CONSTRAINT issuer_keys_sealed_quote_key_check CHECK ((octet_length(sealed_quote_key) = 99)),
    CONSTRAINT issuer_keys_spki_check CHECK ((octet_length(spki) = 342)),
    CONSTRAINT issuer_quote_key_complete CHECK ((((quote_public_key IS NULL) AND (sealed_quote_key IS NULL)) OR ((quote_public_key IS NOT NULL) AND (sealed_quote_key IS NOT NULL))))
);


ALTER TABLE public.issuer_keys OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_quotes; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_lightning_quotes (
    quote_id bytea NOT NULL,
    request bytea NOT NULL,
    key_id bytea NOT NULL,
    batch_hash bytea NOT NULL,
    backend_hash bytea NOT NULL,
    service_key bytea NOT NULL,
    payment_hash bytea NOT NULL,
    sealed_preimage bytea NOT NULL,
    amount_msat numeric(20,0) NOT NULL,
    reserved_at numeric(20,0) NOT NULL,
    price_observed_at numeric(20,0) NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    signed_quote bytea,
    prepared_response bytea,
    prepared_signature bytea,
    settled_amount numeric(20,0),
    settled_at numeric(20,0),
    settle_index numeric(20,0),
    next_attempt numeric(20,0) DEFAULT 0 NOT NULL,
    cancellation bytea,
    policy_version smallint DEFAULT 1 NOT NULL,
    policy_hash bytea DEFAULT sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'::text, 'UTF8'::name)) NOT NULL,
    CONSTRAINT issuer_lightning_quotes_amount_msat_check CHECK (((amount_msat > (0)::numeric) AND (amount_msat <= ('2100000000000000000'::bigint)::numeric))),
    CONSTRAINT issuer_lightning_quotes_backend_hash_check CHECK ((octet_length(backend_hash) = 32)),
    CONSTRAINT issuer_lightning_quotes_batch_hash_check CHECK ((octet_length(batch_hash) = 32)),
    CONSTRAINT issuer_lightning_quotes_check CHECK (((price_observed_at >= (0)::numeric) AND (price_observed_at <= reserved_at))),
    CONSTRAINT issuer_lightning_quotes_check1 CHECK ((((state = 0) AND (signed_quote IS NULL) AND (prepared_response IS NULL) AND (prepared_signature IS NULL)) OR ((state = 1) AND (signed_quote IS NOT NULL) AND (prepared_response IS NULL) AND (prepared_signature IS NULL)) OR ((state = ANY (ARRAY[2, 3])) AND (signed_quote IS NOT NULL) AND (prepared_response IS NOT NULL) AND (prepared_signature IS NOT NULL)) OR (state = ANY (ARRAY[4, 5])))),
    CONSTRAINT issuer_lightning_quotes_check2 CHECK ((((state = 3) AND (settled_amount IS NOT NULL) AND (settled_at IS NOT NULL) AND (settle_index IS NOT NULL)) OR ((state <> 3) AND (settled_amount IS NULL) AND (settled_at IS NULL) AND (settle_index IS NULL)))),
    CONSTRAINT issuer_lightning_quotes_check3 CHECK (((cancellation IS NULL) OR ((state = 4) AND (octet_length(cancellation) = 205)))),
    CONSTRAINT issuer_lightning_quotes_next_attempt_check CHECK (((next_attempt >= (0)::numeric) AND (next_attempt <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_quotes_payment_hash_check CHECK ((octet_length(payment_hash) = 32)),
    CONSTRAINT issuer_lightning_quotes_prepared_response_check CHECK (((octet_length(prepared_response) >= 25670) AND (octet_length(prepared_response) <= 512070))),
    CONSTRAINT issuer_lightning_quotes_prepared_signature_check CHECK ((octet_length(prepared_signature) = 64)),
    CONSTRAINT issuer_lightning_quotes_quote_id_check CHECK ((octet_length(quote_id) = 32)),
    CONSTRAINT issuer_lightning_quotes_request_check CHECK ((octet_length(request) = 72)),
    CONSTRAINT issuer_lightning_quotes_reserved_at_check CHECK (((reserved_at >= (0)::numeric) AND (reserved_at <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_quotes_sealed_preimage_check CHECK ((octet_length(sealed_preimage) = 99)),
    CONSTRAINT issuer_lightning_quotes_service_key_check CHECK ((octet_length(service_key) = 32)),
    CONSTRAINT issuer_lightning_quotes_settle_index_check CHECK (((settle_index > (0)::numeric) AND (settle_index <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_quotes_settled_amount_check CHECK (((settled_amount > (0)::numeric) AND (settled_amount <= ('2100000000000000000'::bigint)::numeric))),
    CONSTRAINT issuer_lightning_quotes_settled_at_check CHECK (((settled_at >= (0)::numeric) AND (settled_at <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_quotes_signed_quote_check CHECK (((octet_length(signed_quote) >= 264) AND (octet_length(signed_quote) <= 7352))),
    CONSTRAINT issuer_lightning_quotes_state_check CHECK (((state >= 0) AND (state <= 5)))
);


ALTER TABLE public.issuer_lightning_quotes OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_revenue; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_lightning_revenue (
    quote_id bytea NOT NULL,
    backend_hash bytea NOT NULL,
    received_msat numeric(20,0) NOT NULL,
    settled_at numeric(20,0) NOT NULL,
    policy_version smallint DEFAULT 1 NOT NULL,
    policy_hash bytea DEFAULT sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'::text, 'UTF8'::name)) NOT NULL,
    CONSTRAINT issuer_lightning_revenue_backend_hash_check CHECK ((octet_length(backend_hash) = 32)),
    CONSTRAINT issuer_lightning_revenue_received_msat_check CHECK (((received_msat > (0)::numeric) AND (received_msat <= ('2100000000000000000'::bigint)::numeric))),
    CONSTRAINT issuer_lightning_revenue_settled_at_check CHECK (((settled_at >= (0)::numeric) AND (settled_at <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_lightning_revenue OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_weekly; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_lightning_weekly (
    batch_id bigint NOT NULL,
    week numeric(20,0) NOT NULL,
    backend_hash bytea NOT NULL,
    policy_version smallint NOT NULL,
    policy_hash bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    witness numeric(20,0) NOT NULL,
    burn numeric(20,0) NOT NULL,
    operations numeric(20,0) NOT NULL,
    carry_before smallint NOT NULL,
    carry_after smallint NOT NULL,
    burn_carry_before smallint NOT NULL,
    burn_carry_after smallint NOT NULL,
    operations_carry_before smallint NOT NULL,
    operations_carry_after smallint NOT NULL,
    reserve_before smallint NOT NULL,
    reserve_after smallint NOT NULL,
    membership_hash bytea NOT NULL,
    CONSTRAINT issuer_lightning_weekly_amount_check CHECK (((amount >= (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_weekly_backend_hash_check CHECK ((octet_length(backend_hash) = 32)),
    CONSTRAINT issuer_lightning_weekly_burn_carry_after_check CHECK (((burn_carry_after >= 0) AND (burn_carry_after <= 9))),
    CONSTRAINT issuer_lightning_weekly_burn_carry_before_check CHECK (((burn_carry_before >= 0) AND (burn_carry_before <= 9))),
    CONSTRAINT issuer_lightning_weekly_burn_check CHECK ((burn >= (0)::numeric)),
    CONSTRAINT issuer_lightning_weekly_carry_after_check CHECK (((carry_after >= 0) AND (carry_after <= 9))),
    CONSTRAINT issuer_lightning_weekly_carry_before_check CHECK (((carry_before >= 0) AND (carry_before <= 9))),
    CONSTRAINT issuer_lightning_weekly_check CHECK ((((policy_version = 1) AND (carry_before <= 4) AND (carry_after <= 4) AND (burn = (0)::numeric) AND (burn_carry_before = 0) AND (burn_carry_after = 0) AND (operations_carry_before = 0) AND (operations_carry_after = 0) AND (reserve_before = 0) AND (reserve_after = 0) AND ((witness + operations) = amount) AND (((witness * (5)::numeric) + (carry_after)::numeric) = (amount + (carry_before)::numeric))) OR ((policy_version = 2) AND (((witness * (10)::numeric) + (carry_after)::numeric) = ((amount * (2)::numeric) + (carry_before)::numeric)) AND (((burn * (10)::numeric) + (burn_carry_after)::numeric) = ((amount * (3)::numeric) + (burn_carry_before)::numeric)) AND (((operations * (10)::numeric) + (operations_carry_after)::numeric) = ((amount * (5)::numeric) + (operations_carry_before)::numeric)) AND (((carry_before + burn_carry_before) + operations_carry_before) = (reserve_before * 10)) AND (((carry_after + burn_carry_after) + operations_carry_after) = (reserve_after * 10)) AND ((((witness + burn) + operations) + (reserve_after)::numeric) = (amount + (reserve_before)::numeric))))),
    CONSTRAINT issuer_lightning_weekly_membership_hash_check CHECK ((octet_length(membership_hash) = 32)),
    CONSTRAINT issuer_lightning_weekly_operations_carry_after_check CHECK (((operations_carry_after >= 0) AND (operations_carry_after <= 9))),
    CONSTRAINT issuer_lightning_weekly_operations_carry_before_check CHECK (((operations_carry_before >= 0) AND (operations_carry_before <= 9))),
    CONSTRAINT issuer_lightning_weekly_operations_check CHECK ((operations >= (0)::numeric)),
    CONSTRAINT issuer_lightning_weekly_reserve_after_check CHECK (((reserve_after >= 0) AND (reserve_after <= 2))),
    CONSTRAINT issuer_lightning_weekly_reserve_before_check CHECK (((reserve_before >= 0) AND (reserve_before <= 2))),
    CONSTRAINT issuer_lightning_weekly_week_check CHECK (((week >= (0)::numeric) AND (week <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_lightning_weekly_witness_check CHECK ((witness >= (0)::numeric))
);


ALTER TABLE public.issuer_lightning_weekly OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_weekly_batch_id_seq; Type: SEQUENCE; Schema: public; Owner: andreyyurlov
--

CREATE SEQUENCE public.issuer_lightning_weekly_batch_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.issuer_lightning_weekly_batch_id_seq OWNER TO andreyyurlov;

--
-- Name: issuer_lightning_weekly_batch_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: andreyyurlov
--

ALTER SEQUENCE public.issuer_lightning_weekly_batch_id_seq OWNED BY public.issuer_lightning_weekly.batch_id;


--
-- Name: issuer_lightning_weekly_events; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_lightning_weekly_events (
    quote_id bytea NOT NULL,
    batch_id bigint NOT NULL
);


ALTER TABLE public.issuer_lightning_weekly_events OWNER TO andreyyurlov;

--
-- Name: issuer_payment_observations; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_payment_observations (
    payment_signature bytea NOT NULL,
    quote_id bytea NOT NULL,
    payer bytea NOT NULL,
    slot numeric(20,0) NOT NULL,
    payment_time numeric(20,0) NOT NULL,
    amount numeric(20,0) NOT NULL,
    wire_sha256 bytea NOT NULL,
    disposition smallint NOT NULL,
    CONSTRAINT issuer_payment_observations_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_payment_observations_disposition_check CHECK ((disposition = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT issuer_payment_observations_payer_check CHECK ((octet_length(payer) = 32)),
    CONSTRAINT issuer_payment_observations_payment_signature_check CHECK ((octet_length(payment_signature) = 64)),
    CONSTRAINT issuer_payment_observations_payment_time_check CHECK (((payment_time >= (0)::numeric) AND (payment_time <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_payment_observations_slot_check CHECK (((slot > (0)::numeric) AND (slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_payment_observations_wire_sha256_check CHECK ((octet_length(wire_sha256) = 32))
);


ALTER TABLE public.issuer_payment_observations OWNER TO andreyyurlov;

--
-- Name: issuer_quotes; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_quotes (
    quote_id bytea NOT NULL,
    quote bytea NOT NULL,
    key_id bytea NOT NULL,
    batch_hash bytea NOT NULL,
    deposit_owner bytea NOT NULL,
    sealed_deposit_key bytea NOT NULL,
    price_observed_at numeric(20,0) NOT NULL,
    payment_signature bytea,
    payment_payer bytea,
    payment_slot numeric(20,0),
    payment_time numeric(20,0),
    payment_amount numeric(20,0),
    issued_response bytea,
    signed_quote bytea,
    policy_version smallint DEFAULT 1 NOT NULL,
    policy_hash bytea DEFAULT sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'::text, 'UTF8'::name)) NOT NULL,
    CONSTRAINT issuer_quotes_batch_hash_check CHECK ((octet_length(batch_hash) = 32)),
    CONSTRAINT issuer_quotes_check CHECK ((((issued_response IS NULL) AND (payment_signature IS NULL) AND (payment_payer IS NULL) AND (payment_slot IS NULL) AND (payment_time IS NULL) AND (payment_amount IS NULL)) OR ((issued_response IS NOT NULL) AND (payment_signature IS NOT NULL) AND (payment_payer IS NOT NULL) AND (payment_slot IS NOT NULL) AND (payment_time IS NOT NULL) AND (payment_amount IS NOT NULL)))),
    CONSTRAINT issuer_quotes_deposit_owner_check CHECK ((octet_length(deposit_owner) = 32)),
    CONSTRAINT issuer_quotes_issued_response_check CHECK (((octet_length(issued_response) >= 25670) AND (octet_length(issued_response) <= 512070))),
    CONSTRAINT issuer_quotes_payment_amount_check CHECK ((payment_amount > (0)::numeric)),
    CONSTRAINT issuer_quotes_payment_payer_check CHECK ((octet_length(payment_payer) = 32)),
    CONSTRAINT issuer_quotes_payment_signature_check CHECK ((octet_length(payment_signature) = 64)),
    CONSTRAINT issuer_quotes_payment_slot_check CHECK ((payment_slot > (0)::numeric)),
    CONSTRAINT issuer_quotes_payment_time_check CHECK ((payment_time >= (0)::numeric)),
    CONSTRAINT issuer_quotes_price_observed_at_check CHECK ((price_observed_at >= (0)::numeric)),
    CONSTRAINT issuer_quotes_quote_check CHECK ((octet_length(quote) = 224)),
    CONSTRAINT issuer_quotes_quote_id_check CHECK ((octet_length(quote_id) = 32)),
    CONSTRAINT issuer_quotes_sealed_deposit_key_check CHECK ((octet_length(sealed_deposit_key) = 99)),
    CONSTRAINT issuer_quotes_signed_quote_check CHECK ((octet_length(signed_quote) = 292))
);


ALTER TABLE public.issuer_quotes OWNER TO andreyyurlov;

--
-- Name: issuer_revenue_policies; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_revenue_policies (
    policy_version smallint NOT NULL,
    policy_hash bytea NOT NULL,
    CONSTRAINT issuer_revenue_policies_policy_hash_check CHECK ((octet_length(policy_hash) = 32)),
    CONSTRAINT issuer_revenue_policies_policy_version_check CHECK ((policy_version = ANY (ARRAY[1, 2])))
);


ALTER TABLE public.issuer_revenue_policies OWNER TO andreyyurlov;

--
-- Name: issuer_transparency_cursor; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_transparency_cursor (
    singleton boolean NOT NULL,
    checkpoint bytea NOT NULL,
    CONSTRAINT issuer_transparency_cursor_singleton_check CHECK (singleton)
);


ALTER TABLE public.issuer_transparency_cursor OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_attempts; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_attempts (
    transaction_signature bytea NOT NULL,
    movement_id bytea NOT NULL,
    nonce_address bytea NOT NULL,
    nonce_value bytea NOT NULL,
    message bytea NOT NULL,
    packet bytea NOT NULL,
    state smallint NOT NULL,
    finalized_slot numeric(20,0),
    execution_error text,
    fee numeric(20,0),
    CONSTRAINT issuer_treasury_attempts_check CHECK ((((state = 1) AND (finalized_slot IS NULL) AND (execution_error IS NULL) AND (fee IS NULL)) OR ((state = 2) AND (finalized_slot IS NOT NULL) AND (execution_error IS NULL) AND (fee IS NOT NULL)) OR ((state = 3) AND (finalized_slot IS NOT NULL) AND (execution_error IS NOT NULL) AND (fee IS NOT NULL)))),
    CONSTRAINT issuer_treasury_attempts_execution_error_check CHECK ((octet_length(execution_error) <= 2048)),
    CONSTRAINT issuer_treasury_attempts_fee_check CHECK (((fee >= (0)::numeric) AND (fee <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_attempts_finalized_slot_check CHECK (((finalized_slot > (0)::numeric) AND (finalized_slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_attempts_message_check CHECK (((octet_length(message) >= 1) AND (octet_length(message) <= 1232))),
    CONSTRAINT issuer_treasury_attempts_nonce_address_check CHECK ((octet_length(nonce_address) = 32)),
    CONSTRAINT issuer_treasury_attempts_nonce_value_check CHECK ((octet_length(nonce_value) = 32)),
    CONSTRAINT issuer_treasury_attempts_packet_check CHECK (((octet_length(packet) >= 1) AND (octet_length(packet) <= 1232))),
    CONSTRAINT issuer_treasury_attempts_state_check CHECK ((state = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT issuer_treasury_attempts_transaction_signature_check CHECK ((octet_length(transaction_signature) = 64))
);


ALTER TABLE public.issuer_treasury_attempts OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_batch_attempts; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_batch_attempts (
    transaction_signature bytea NOT NULL,
    batch_id bytea NOT NULL,
    nonce_address bytea NOT NULL,
    nonce_value bytea NOT NULL,
    message bytea NOT NULL,
    packet bytea NOT NULL,
    state smallint NOT NULL,
    finalized_slot numeric(20,0),
    execution_error text,
    fee numeric(20,0),
    rent numeric(20,0),
    CONSTRAINT issuer_treasury_batch_attempts_check CHECK ((((state = 1) AND (finalized_slot IS NULL) AND (execution_error IS NULL) AND (fee IS NULL) AND (rent IS NULL)) OR ((state = 2) AND (finalized_slot > (0)::numeric) AND (execution_error IS NULL) AND (fee >= (0)::numeric) AND (rent >= (0)::numeric)) OR ((state = 3) AND (finalized_slot > (0)::numeric) AND (execution_error IS NOT NULL) AND (fee >= (0)::numeric) AND (rent = (0)::numeric)))),
    CONSTRAINT issuer_treasury_batch_attempts_message_check CHECK (((octet_length(message) >= 1) AND (octet_length(message) <= 1232))),
    CONSTRAINT issuer_treasury_batch_attempts_nonce_address_check CHECK ((octet_length(nonce_address) = 32)),
    CONSTRAINT issuer_treasury_batch_attempts_nonce_value_check CHECK ((octet_length(nonce_value) = 32)),
    CONSTRAINT issuer_treasury_batch_attempts_packet_check CHECK (((octet_length(packet) >= 1) AND (octet_length(packet) <= 1232))),
    CONSTRAINT issuer_treasury_batch_attempts_state_check CHECK ((state = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT issuer_treasury_batch_attempts_transaction_signature_check CHECK ((octet_length(transaction_signature) = 64))
);


ALTER TABLE public.issuer_treasury_batch_attempts OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_batch_costs; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_batch_costs (
    transaction_signature bytea NOT NULL,
    movement_id bytea NOT NULL,
    fee numeric(20,0) NOT NULL,
    rent numeric(20,0) NOT NULL,
    CONSTRAINT issuer_treasury_batch_costs_fee_check CHECK (((fee >= (0)::numeric) AND (fee <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_batch_costs_rent_check CHECK (((rent >= (0)::numeric) AND (rent <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_treasury_batch_costs OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_batch_members; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_batch_members (
    movement_id bytea NOT NULL,
    batch_id bytea NOT NULL,
    ordinal smallint NOT NULL,
    CONSTRAINT issuer_treasury_batch_members_ordinal_check CHECK (((ordinal >= 0) AND (ordinal <= 3)))
);


ALTER TABLE public.issuer_treasury_batch_members OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_batches; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_batches (
    batch_id bytea NOT NULL,
    config_hash bytea NOT NULL,
    member_hash bytea NOT NULL,
    member_count smallint NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    nonce_address bytea,
    nonce_value bytea,
    message bytea,
    packet bytea,
    transaction_signature bytea,
    finalized_slot numeric(20,0),
    execution_error text,
    fee numeric(20,0),
    rent numeric(20,0),
    CONSTRAINT issuer_treasury_batches_batch_id_check CHECK ((octet_length(batch_id) = 32)),
    CONSTRAINT issuer_treasury_batches_check CHECK ((((message IS NULL) AND (nonce_address IS NULL) AND (nonce_value IS NULL)) OR ((message IS NOT NULL) AND (nonce_address IS NOT NULL) AND (nonce_value IS NOT NULL)))),
    CONSTRAINT issuer_treasury_batches_check1 CHECK ((((state = 0) AND (packet IS NULL) AND (transaction_signature IS NULL)) OR ((state = ANY (ARRAY[1, 2, 3, 4])) AND (message IS NOT NULL) AND (packet IS NOT NULL) AND (transaction_signature IS NOT NULL)))),
    CONSTRAINT issuer_treasury_batches_check2 CHECK ((((state = ANY (ARRAY[0, 1, 4])) AND (finalized_slot IS NULL) AND (fee IS NULL) AND (rent IS NULL) AND (execution_error IS NULL)) OR ((state = 2) AND (finalized_slot IS NOT NULL) AND (fee IS NOT NULL) AND (rent IS NOT NULL) AND (execution_error IS NULL)) OR ((state = 3) AND (finalized_slot IS NOT NULL) AND (fee IS NOT NULL) AND (rent = (0)::numeric) AND (execution_error IS NOT NULL)))),
    CONSTRAINT issuer_treasury_batches_config_hash_check CHECK ((octet_length(config_hash) = 32)),
    CONSTRAINT issuer_treasury_batches_execution_error_check CHECK ((octet_length(execution_error) <= 2048)),
    CONSTRAINT issuer_treasury_batches_fee_check CHECK (((fee >= (0)::numeric) AND (fee <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_batches_finalized_slot_check CHECK (((finalized_slot > (0)::numeric) AND (finalized_slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_batches_member_count_check CHECK (((member_count >= 1) AND (member_count <= 4))),
    CONSTRAINT issuer_treasury_batches_member_hash_check CHECK ((octet_length(member_hash) = 32)),
    CONSTRAINT issuer_treasury_batches_message_check CHECK (((octet_length(message) >= 1) AND (octet_length(message) <= 1232))),
    CONSTRAINT issuer_treasury_batches_nonce_address_check CHECK ((octet_length(nonce_address) = 32)),
    CONSTRAINT issuer_treasury_batches_nonce_value_check CHECK ((octet_length(nonce_value) = 32)),
    CONSTRAINT issuer_treasury_batches_packet_check CHECK (((octet_length(packet) >= 1) AND (octet_length(packet) <= 1232))),
    CONSTRAINT issuer_treasury_batches_rent_check CHECK (((rent >= (0)::numeric) AND (rent <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_batches_state_check CHECK (((state >= 0) AND (state <= 4))),
    CONSTRAINT issuer_treasury_batches_transaction_signature_check CHECK ((octet_length(transaction_signature) = 64))
);


ALTER TABLE public.issuer_treasury_batches OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_burn_intents; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_burn_intents (
    intent_id bytea NOT NULL,
    config_hash bytea NOT NULL,
    token_program bytea NOT NULL,
    payer bytea NOT NULL,
    profile bytea NOT NULL,
    epoch numeric(20,0) NOT NULL,
    cash numeric(20,0) NOT NULL,
    carry numeric(20,0) NOT NULL,
    instruction bytea NOT NULL,
    membership_hash bytea NOT NULL,
    funding_hash bytea NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    finalized_slot numeric(20,0),
    week_frame bytea,
    close_receipt bytea,
    expiry_slot numeric(20,0),
    expiry_frame bytea,
    expiry_receipt bytea,
    CONSTRAINT issuer_burn_intent_state CHECK ((state = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT issuer_burn_intent_terminal CHECK ((((state = 0) AND (finalized_slot IS NULL) AND (week_frame IS NULL) AND (close_receipt IS NULL) AND (expiry_slot IS NULL) AND (expiry_frame IS NULL) AND (expiry_receipt IS NULL)) OR ((state = 1) AND (finalized_slot IS NOT NULL) AND (week_frame IS NOT NULL) AND (expiry_slot IS NULL) AND (expiry_frame IS NULL) AND (expiry_receipt IS NULL)) OR ((state = 2) AND (finalized_slot IS NULL) AND (week_frame IS NULL) AND (close_receipt IS NULL) AND (expiry_slot IS NOT NULL) AND (expiry_frame IS NOT NULL) AND (expiry_receipt IS NOT NULL)))),
    CONSTRAINT issuer_treasury_burn_intents_carry_check CHECK (((carry >= (0)::numeric) AND (carry <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_cash_check CHECK (((cash > (0)::numeric) AND (cash <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_check CHECK ((((cash + carry) >= (24)::numeric) AND ((cash + carry) <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_close_receipt_check CHECK ((octet_length(close_receipt) = 256)),
    CONSTRAINT issuer_treasury_burn_intents_config_hash_check CHECK ((octet_length(config_hash) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_epoch_check CHECK (((epoch >= (0)::numeric) AND (epoch <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_expiry_frame_check CHECK ((octet_length(expiry_frame) = 192)),
    CONSTRAINT issuer_treasury_burn_intents_expiry_receipt_check CHECK ((octet_length(expiry_receipt) = 256)),
    CONSTRAINT issuer_treasury_burn_intents_expiry_slot_check CHECK (((expiry_slot > (0)::numeric) AND (expiry_slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_finalized_slot_check CHECK (((finalized_slot > (0)::numeric) AND (finalized_slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_intents_funding_hash_check CHECK ((octet_length(funding_hash) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_instruction_check CHECK (((octet_length(instruction) = 313) AND (get_byte(instruction, 0) = 14))),
    CONSTRAINT issuer_treasury_burn_intents_intent_id_check CHECK ((octet_length(intent_id) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_membership_hash_check CHECK ((octet_length(membership_hash) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_payer_check CHECK ((octet_length(payer) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_profile_check CHECK ((octet_length(profile) = 320)),
    CONSTRAINT issuer_treasury_burn_intents_token_program_check CHECK ((octet_length(token_program) = 32)),
    CONSTRAINT issuer_treasury_burn_intents_week_frame_check CHECK ((octet_length(week_frame) = 2240))
);


ALTER TABLE public.issuer_treasury_burn_intents OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_burn_liabilities; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_burn_liabilities (
    batch_id bigint NOT NULL,
    amount numeric(20,0) NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    funding_hash bytea,
    receipt bytea,
    CONSTRAINT issuer_treasury_burn_liabilities_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_burn_liabilities_check CHECK ((((state = 0) AND (funding_hash IS NULL) AND (receipt IS NULL)) OR ((state = 1) AND (funding_hash IS NOT NULL) AND (receipt IS NOT NULL)))),
    CONSTRAINT issuer_treasury_burn_liabilities_funding_hash_check CHECK ((octet_length(funding_hash) = 32)),
    CONSTRAINT issuer_treasury_burn_liabilities_state_check CHECK ((state = ANY (ARRAY[0, 1])))
);


ALTER TABLE public.issuer_treasury_burn_liabilities OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_burn_members; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_burn_members (
    batch_id bigint NOT NULL,
    intent_id bytea NOT NULL,
    released boolean DEFAULT false NOT NULL
);


ALTER TABLE public.issuer_treasury_burn_members OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_funding_jobs; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_funding_jobs (
    batch_id bigint NOT NULL,
    next_attempt numeric(20,0) NOT NULL,
    CONSTRAINT issuer_treasury_funding_jobs_next_attempt_check CHECK (((next_attempt >= (0)::numeric) AND (next_attempt <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_treasury_funding_jobs OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_keys; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_keys (
    service_key bytea NOT NULL,
    purpose smallint NOT NULL,
    role smallint NOT NULL,
    public_key bytea NOT NULL,
    sealed_key bytea NOT NULL,
    CONSTRAINT issuer_treasury_keys_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT issuer_treasury_keys_purpose_check CHECK ((purpose = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_treasury_keys_role_check CHECK ((role = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_treasury_keys_sealed_key_check CHECK (((octet_length(sealed_key) >= 68) AND (octet_length(sealed_key) <= 1024))),
    CONSTRAINT issuer_treasury_keys_service_key_check CHECK ((octet_length(service_key) = 32))
);


ALTER TABLE public.issuer_treasury_keys OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_movements; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_movements (
    movement_id bytea NOT NULL,
    payment_signature bytea NOT NULL,
    kind smallint NOT NULL,
    config_hash bytea NOT NULL,
    source bytea NOT NULL,
    destination bytea NOT NULL,
    destination_owner bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    ready_at numeric(20,0) NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    nonce_address bytea,
    nonce_value bytea,
    message bytea,
    packet bytea,
    transaction_signature bytea,
    finalized_slot numeric(20,0),
    execution_error text,
    fee numeric(20,0),
    batch_id bytea,
    rent numeric(20,0) DEFAULT 0 NOT NULL,
    CONSTRAINT issuer_treasury_movements_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_movements_check CHECK ((((message IS NULL) AND (nonce_address IS NULL) AND (nonce_value IS NULL)) OR ((message IS NOT NULL) AND (nonce_address IS NOT NULL) AND (nonce_value IS NOT NULL)))),
    CONSTRAINT issuer_treasury_movements_check1 CHECK ((((state = 0) AND (packet IS NULL) AND (transaction_signature IS NULL)) OR ((state = ANY (ARRAY[1, 2, 3, 4])) AND (message IS NOT NULL) AND (packet IS NOT NULL) AND (transaction_signature IS NOT NULL)))),
    CONSTRAINT issuer_treasury_movements_check2 CHECK ((((state = ANY (ARRAY[0, 1, 4])) AND (finalized_slot IS NULL) AND (fee IS NULL) AND (execution_error IS NULL)) OR ((state = 2) AND (finalized_slot IS NOT NULL) AND (fee IS NOT NULL) AND (execution_error IS NULL)) OR ((state = 3) AND (finalized_slot IS NOT NULL) AND (fee IS NOT NULL) AND (execution_error IS NOT NULL)))),
    CONSTRAINT issuer_treasury_movements_config_hash_check CHECK ((octet_length(config_hash) = 32)),
    CONSTRAINT issuer_treasury_movements_destination_check CHECK ((octet_length(destination) = 32)),
    CONSTRAINT issuer_treasury_movements_destination_owner_check CHECK ((octet_length(destination_owner) = 32)),
    CONSTRAINT issuer_treasury_movements_execution_error_check CHECK ((octet_length(execution_error) <= 2048)),
    CONSTRAINT issuer_treasury_movements_fee_check CHECK (((fee >= (0)::numeric) AND (fee <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_movements_finalized_slot_check CHECK (((finalized_slot > (0)::numeric) AND (finalized_slot <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_movements_kind_check CHECK ((kind = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_treasury_movements_message_check CHECK (((octet_length(message) >= 1) AND (octet_length(message) <= 1232))),
    CONSTRAINT issuer_treasury_movements_movement_id_check CHECK ((octet_length(movement_id) = 32)),
    CONSTRAINT issuer_treasury_movements_nonce_address_check CHECK ((octet_length(nonce_address) = 32)),
    CONSTRAINT issuer_treasury_movements_nonce_value_check CHECK ((octet_length(nonce_value) = 32)),
    CONSTRAINT issuer_treasury_movements_packet_check CHECK (((octet_length(packet) >= 1) AND (octet_length(packet) <= 1232))),
    CONSTRAINT issuer_treasury_movements_ready_at_check CHECK (((ready_at >= (0)::numeric) AND (ready_at <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_movements_rent_check CHECK (((rent >= (0)::numeric) AND (rent <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_movements_source_check CHECK ((octet_length(source) = 32)),
    CONSTRAINT issuer_treasury_movements_state_check CHECK (((state >= 0) AND (state <= 4))),
    CONSTRAINT issuer_treasury_movements_transaction_signature_check CHECK ((octet_length(transaction_signature) = 64))
);


ALTER TABLE public.issuer_treasury_movements OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_nonce_lanes; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_nonce_lanes (
    nonce_address bytea NOT NULL,
    owner_kind smallint NOT NULL,
    owner_id bytea NOT NULL,
    CONSTRAINT issuer_treasury_nonce_lanes_nonce_address_check CHECK ((octet_length(nonce_address) = 32)),
    CONSTRAINT issuer_treasury_nonce_lanes_owner_id_check CHECK ((octet_length(owner_id) = 32)),
    CONSTRAINT issuer_treasury_nonce_lanes_owner_kind_check CHECK ((owner_kind = ANY (ARRAY[0, 1])))
);


ALTER TABLE public.issuer_treasury_nonce_lanes OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_observation_jobs; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_observation_jobs (
    config_hash bytea NOT NULL,
    quote_id bytea NOT NULL,
    next_attempt numeric(20,0) NOT NULL,
    CONSTRAINT issuer_treasury_observation_jobs_config_hash_check CHECK ((octet_length(config_hash) = 32)),
    CONSTRAINT issuer_treasury_observation_jobs_next_attempt_check CHECK (((next_attempt >= (0)::numeric) AND (next_attempt <= '18446744073709551615'::numeric)))
);


ALTER TABLE public.issuer_treasury_observation_jobs OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_rewards_intents; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_rewards_intents (
    intent_id bytea NOT NULL,
    batch_id bigint NOT NULL,
    epoch numeric(20,0) NOT NULL,
    pool bytea NOT NULL,
    funder bytea NOT NULL,
    source bytea NOT NULL,
    mint bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    receipt bytea,
    CONSTRAINT issuer_treasury_rewards_intents_amount_check CHECK (((amount > (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_rewards_intents_check CHECK ((((state = 1) AND (receipt IS NOT NULL)) OR ((state = ANY (ARRAY[0, 2])) AND (receipt IS NULL)))),
    CONSTRAINT issuer_treasury_rewards_intents_epoch_check CHECK (((epoch >= (0)::numeric) AND (epoch <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_rewards_intents_funder_check CHECK ((octet_length(funder) = 32)),
    CONSTRAINT issuer_treasury_rewards_intents_intent_id_check CHECK ((octet_length(intent_id) = 32)),
    CONSTRAINT issuer_treasury_rewards_intents_mint_check CHECK ((octet_length(mint) = 32)),
    CONSTRAINT issuer_treasury_rewards_intents_pool_check CHECK ((octet_length(pool) = 32)),
    CONSTRAINT issuer_treasury_rewards_intents_receipt_check CHECK ((octet_length(receipt) = 192)),
    CONSTRAINT issuer_treasury_rewards_intents_source_check CHECK ((octet_length(source) = 32)),
    CONSTRAINT issuer_treasury_rewards_intents_state_check CHECK ((state = ANY (ARRAY[0, 1, 2])))
);


ALTER TABLE public.issuer_treasury_rewards_intents OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_weekly; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_weekly (
    batch_id bigint NOT NULL,
    week numeric(20,0) NOT NULL,
    asset smallint NOT NULL,
    cutoff bigint NOT NULL,
    mint bytea NOT NULL,
    config_hash bytea NOT NULL,
    amount numeric(20,0) NOT NULL,
    witness numeric(20,0) NOT NULL,
    operations numeric(20,0) NOT NULL,
    carry_before smallint NOT NULL,
    carry_after smallint NOT NULL,
    membership_hash bytea NOT NULL,
    policy_version smallint DEFAULT 1 NOT NULL,
    policy_hash bytea DEFAULT sha256(convert_to('morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5'::text, 'UTF8'::name)) NOT NULL,
    burn numeric(20,0) DEFAULT 0 NOT NULL,
    burn_carry_before smallint DEFAULT 0 NOT NULL,
    burn_carry_after smallint DEFAULT 0 NOT NULL,
    operations_carry_before smallint DEFAULT 0 NOT NULL,
    operations_carry_after smallint DEFAULT 0 NOT NULL,
    reserve_before smallint DEFAULT 0 NOT NULL,
    reserve_after smallint DEFAULT 0 NOT NULL,
    CONSTRAINT issuer_treasury_weekly_amount_check CHECK (((amount >= (0)::numeric) AND (amount <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_weekly_asset_check CHECK ((asset = ANY (ARRAY[0, 1]))),
    CONSTRAINT issuer_treasury_weekly_burn_carry_after_check CHECK (((burn_carry_after >= 0) AND (burn_carry_after <= 9))),
    CONSTRAINT issuer_treasury_weekly_burn_carry_before_check CHECK (((burn_carry_before >= 0) AND (burn_carry_before <= 9))),
    CONSTRAINT issuer_treasury_weekly_burn_check CHECK (((burn >= (0)::numeric) AND (burn <= '18446744073709551615'::numeric))),
    CONSTRAINT issuer_treasury_weekly_check CHECK ((((carry_before >= 0) AND (carry_before <= 9)) AND ((carry_after >= 0) AND (carry_after <= 9)))),
    CONSTRAINT issuer_treasury_weekly_config_hash_check CHECK ((octet_length(config_hash) = 32)),
    CONSTRAINT issuer_treasury_weekly_cutoff_check CHECK ((cutoff >= 0)),
    CONSTRAINT issuer_treasury_weekly_membership_hash_check CHECK ((octet_length(membership_hash) = 32)),
    CONSTRAINT issuer_treasury_weekly_mint_check CHECK ((octet_length(mint) = 32)),
    CONSTRAINT issuer_treasury_weekly_operations_carry_after_check CHECK (((operations_carry_after >= 0) AND (operations_carry_after <= 9))),
    CONSTRAINT issuer_treasury_weekly_operations_carry_before_check CHECK (((operations_carry_before >= 0) AND (operations_carry_before <= 9))),
    CONSTRAINT issuer_treasury_weekly_operations_check CHECK ((operations >= (0)::numeric)),
    CONSTRAINT issuer_treasury_weekly_policy_math CHECK ((((policy_version = 1) AND (carry_before <= 4) AND (carry_after <= 4) AND (burn = (0)::numeric) AND (burn_carry_before = 0) AND (burn_carry_after = 0) AND (operations_carry_before = 0) AND (operations_carry_after = 0) AND (reserve_before = 0) AND (reserve_after = 0) AND ((witness + operations) = amount) AND (((witness * (5)::numeric) + (carry_after)::numeric) = (amount + (carry_before)::numeric))) OR ((policy_version = 2) AND (((witness * (10)::numeric) + (carry_after)::numeric) = ((amount * (2)::numeric) + (carry_before)::numeric)) AND (((burn * (10)::numeric) + (burn_carry_after)::numeric) = ((amount * (3)::numeric) + (burn_carry_before)::numeric)) AND (((operations * (10)::numeric) + (operations_carry_after)::numeric) = ((amount * (5)::numeric) + (operations_carry_before)::numeric)) AND (((carry_before + burn_carry_before) + operations_carry_before) = (reserve_before * 10)) AND (((carry_after + burn_carry_after) + operations_carry_after) = (reserve_after * 10)) AND ((((witness + burn) + operations) + (reserve_after)::numeric) = (amount + (reserve_before)::numeric))))),
    CONSTRAINT issuer_treasury_weekly_reserve_after_check CHECK (((reserve_after >= 0) AND (reserve_after <= 2))),
    CONSTRAINT issuer_treasury_weekly_reserve_before_check CHECK (((reserve_before >= 0) AND (reserve_before <= 2))),
    CONSTRAINT issuer_treasury_weekly_week_check CHECK ((week >= (0)::numeric)),
    CONSTRAINT issuer_treasury_weekly_witness_check CHECK ((witness >= (0)::numeric))
);


ALTER TABLE public.issuer_treasury_weekly OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_weekly_batch_id_seq; Type: SEQUENCE; Schema: public; Owner: andreyyurlov
--

CREATE SEQUENCE public.issuer_treasury_weekly_batch_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.issuer_treasury_weekly_batch_id_seq OWNER TO andreyyurlov;

--
-- Name: issuer_treasury_weekly_batch_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: andreyyurlov
--

ALTER SEQUENCE public.issuer_treasury_weekly_batch_id_seq OWNED BY public.issuer_treasury_weekly.batch_id;


--
-- Name: issuer_treasury_weekly_events; Type: TABLE; Schema: public; Owner: andreyyurlov
--

CREATE TABLE public.issuer_treasury_weekly_events (
    event_id bigint NOT NULL,
    batch_id bigint NOT NULL
);


ALTER TABLE public.issuer_treasury_weekly_events OWNER TO andreyyurlov;

--
-- Name: issuer_credit_revenue event_id; Type: DEFAULT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue ALTER COLUMN event_id SET DEFAULT nextval('public.issuer_credit_revenue_event_id_seq'::regclass);


--
-- Name: issuer_lightning_weekly batch_id; Type: DEFAULT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly ALTER COLUMN batch_id SET DEFAULT nextval('public.issuer_lightning_weekly_batch_id_seq'::regclass);


--
-- Name: issuer_treasury_weekly batch_id; Type: DEFAULT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly ALTER COLUMN batch_id SET DEFAULT nextval('public.issuer_treasury_weekly_batch_id_seq'::regclass);


--
-- Data for Name: issuer_btc_conversion_accounting; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_accounting (intent_id, actual_routing_fee_msat, actual_btc_fee_msat, actual_usdc_fee_100ths, lnd_residual_msat, provider_btc_residual_msat, provider_usdc_residual_100ths, provider_net_usdc) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	0	0	9979800	1000	100000	0	49799202
\.


--
-- Data for Name: issuer_btc_conversion_artifacts; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_artifacts (intent_id, kind, body, body_sha256) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	preflight-method-0-b3647e49d6bed0483437585f4320a54ebcca8df43c187ab0ddd41ad6d3628ebe	{"methods":[{"method_id":"11111111-2222-3333-4444-555555555555","withdrawal":{},"asset":{"class":"currency","name":"USDC"},"network":{"network_id":"66666666-7777-8888-9999-aaaaaaaaaaaa","network_name":"Solana","contract_address":"Dw5JbBf8sSj3gJujGy4HTCM3wCSQvkiUVc5hixV8oJ4y"},"minimum_amount":"1","maximum_amount":"1000000"}]}	\\xb3647e49d6bed0483437585f4320a54ebcca8df43c187ab0ddd41ad6d3628ebe
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	preflight-address-0-963d36af2ffb2a1c28e0a15690a0277bd00b932caa0a2c6d75c6196a0ad4e831	{"addresses":[{"address_id":"AB7J4FF-BGM7G-V2JMIH","scope":{"method_id":"11111111-2222-3333-4444-555555555555"},"verified":true,"address_details":{"crypto":{"address":"3CF48HwS4araR6dysSKeQu3zrVMZA5Xg9S96egMXVT1x"}}}]}	\\x963d36af2ffb2a1c28e0a15690a0277bd00b932caa0a2c6d75c6196a0ad4e831
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	invoice-response	{"error":[],"result":[{"address":"lnbcrt499990n1p4d50tmpp50jh3e4zxf4azmpfhnr9v5mhtxxv6k3v9tans5uym4hm9zpjm8p0qdp0damkuetyypc8ymmkd9jx2u3qgf2yxgrrdah8vetjwd5k7mscqzzsxqzuysp5ucn0kjfy4sgq8vl86snscv50pwhm7rskmm4xd6hs37taqmymffyq9qxpqysgqv6nz5q6ad3sckmv0kt4n8x9a40z7lw0hw392e5gsy3djfw3hmtwph5pnmnc52p2d9nnyyfkkt6ter8lzcu3vxh5u0phvc3jrjxvt4hgqe00vl6","expiretm":"0","new":true}]}	\\x8766280f2d767644d45ff217f5e640b7db9b2facb2a7325ae91ed7f8275d1262
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	payment	{"result":{"payment_hash":"7caf1cd4464d7a2d853798caca6eeb3199ab45855f670a709badf651065b385e","value":"49999","creation_date":"1792687483","fee":"0","payment_preimage":"3434d95a9c4d79d920516874fe29dfc8bd9a6dc198ad6fd473233cd547b02701","value_sat":"49999","value_msat":"49999000","payment_request":"lnbcrt499990n1p4d50tmpp50jh3e4zxf4azmpfhnr9v5mhtxxv6k3v9tans5uym4hm9zpjm8p0qdp0damkuetyypc8ymmkd9jx2u3qgf2yxgrrdah8vetjwd5k7mscqzzsxqzuysp5ucn0kjfy4sgq8vl86snscv50pwhm7rskmm4xd6hs37taqmymffyq9qxpqysgqv6nz5q6ad3sckmv0kt4n8x9a40z7lw0hw392e5gsy3djfw3hmtwph5pnmnc52p2d9nnyyfkkt6ter8lzcu3vxh5u0phvc3jrjxvt4hgqe00vl6","status":"SUCCEEDED","fee_sat":"0","fee_msat":"0","creation_time_ns":"1792687483857576000","htlcs":[{"attempt_id":"1","status":"SUCCEEDED","route":{"total_time_lock":196,"total_fees":"0","total_amt":"49999","hops":[{"chan_id":"118747255865344","chan_capacity":"49999","amt_to_forward":"49999","fee":"0","expiry":196,"amt_to_forward_msat":"49999000","fee_msat":"0","pub_key":"027a8cfa2dbea1ac4a7c71eb5ac3b880584ca1e4a1d2de8ec780a8f52e11dfb405","tlv_payload":true,"mpp_record":{"payment_addr":"5ib7SSSsEAOz59QnDDKPC6+/Dhbe6mbq8I+X0GybSkg=","total_amt_msat":"49999000"},"amp_record":null,"custom_records":{},"metadata":"","blinding_point":"","encrypted_data":"","total_amt_msat":"0"}],"total_fees_msat":"0","total_amt_msat":"49999000","first_hop_amount_msat":"49999000","custom_channel_data":""},"attempt_time_ns":"1792687483878797000","resolve_time_ns":"1792687484066924000","failure":null,"preimage":"NDTZWpxNedkgUWh0/infyL2abcGYrW/UcyM81UewJwE="}],"payment_index":"1","failure_reason":"FAILURE_REASON_NONE","first_hop_custom_records":{"106823":"AA=="}}}	\\x5effcac25d24e6c6a9671a92367679ffd10fd4f0acfd25eebee6a5d73adf4be7
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	order-ack	{"error":[],"result":{"txid":["ORDER-1"]}}	\\x4649ad18d1594afd388959d9475d512374d2d43125828bc463d0f8da8ce72c38
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	order-status	{"error":[],"result":{"ORDER-1":{"cl_ord_id":"36f0a33b5a1b474a680bd236a4f65e13","time_in_force":"fok","descr":{"pair":"XBTUSDC","type":"sell","ordertype":"limit","price":"99600","leverage":"none","close":""},"vol":"0.00049899","vol_exec":"0.00049899","status":"closed","cost":"49.899","trades":["TRADE-1"]}}}	\\xa54cfb36a2e0bbb6d211882908e7a30708edd2b699565d9e5faa078a331a2c66
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	trades	{"error":[],"result":{"TRADE-1":{"ordertxid":"ORDER-1","pair":"XBTUSDC","type":"sell","ordertype":"limit","margin":"0","vol":"0.00049899","cost":"49.899","ledgers":["L-BTC","L-USDC"]}}}	\\x7ce547bb54c477d052ed6bc8b74c0085af58898db410653bafff56e2ff7588a0
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	ledgers	{"error":[],"result":{"L-BTC":{"refid":"TRADE-1","type":"trade","aclass":"currency","asset":"XXBT","amount":"-0.00049899","fee":"0","balance":"999999999"},"L-USDC":{"refid":"TRADE-1","type":"trade","aclass":"currency","asset":"USDC","amount":"49.899","fee":"0.099798","balance":"999999999"}}}	\\x28ebc25934d37a6848a01669e3270fbfbaa37a07377808c239b6ab8958b162ca
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-ack	{"withdrawal_id":"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx","gross_amount":{"asset_amount":{"asset":{"class":"currency","name":"USDC"},"amount":"49.799202"}},"net_amount":{"asset_amount":{"asset":{"class":"currency","name":"USDC"},"amount":"49.699202"}},"fee":{"asset_amount":{"asset":{"class":"currency","name":"USDC"},"amount":"0.1"}}}	\\xf6ab3c1eb21e4ef39089e405d9da8f8cd89d4530caa0412dd977435d14f4de76
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-000	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-001	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"pending\\"}]}"}	\\x2461228ce30474f149a958aa14bb8d66264f775f8a9b8b4ca62c7df9d485eaa8
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-page-refused-9e3719ab73566269749754d6b553fc2d	{"withdrawals":[{"withdrawal_id":"UNRELATED-WITHDRAWAL"}],"next_cursor":null}	\\x9e3719ab73566269749754d6b553fc2ddc96cd43bc4d5a966ec5e6abf0ea9822
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-002	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-page-refused-8a3ab0e767bf6a40a7ab24c0c0029538	{"withdrawals":[],"next_cursor":"page+/=2"}	\\x8a3ab0e767bf6a40a7ab24c0c0029538c7a06c31eb24ecb9036d71cae38ef061
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-003	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-004	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-005	{"request_cursor":"page+/=2","next_cursor":"page+/=3","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-2\\"}],\\"next_cursor\\":\\"page+/=3\\"}"}	\\xfb45d0c8d11060fc6acc59f2c612130b5eb48a84c1a9b8242fb9ec973703d748
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-006	{"request_cursor":"page+/=3","next_cursor":"page+/=4","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-3\\"}],\\"next_cursor\\":\\"page+/=4\\"}"}	\\x82731b75ccc5b014d452b92c7ba04aed8564dbdb76a4faaa2594cee65543a60b
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-007	{"request_cursor":"page+/=4","next_cursor":"page+/=5","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-4\\"}],\\"next_cursor\\":\\"page+/=5\\"}"}	\\x0ba46e971d01bc344ce18b02f5b6d22d26e40d288e335a46f45fc5bb67a3d8d6
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-008	{"request_cursor":"page+/=5","next_cursor":"page+/=6","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-5\\"}],\\"next_cursor\\":\\"page+/=6\\"}"}	\\x5a507e5f789c00d5cb9044ea97aa8be0817fa616d08b36caf7f38a165bd009ec
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-009	{"request_cursor":"page+/=6","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x6ce74cfac8732b678bc80cbec6b18273b64821d53e75c3957847f09061cd54ba
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-010	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-011	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-012	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-013	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-014	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-015	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-016	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-017	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-018	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-019	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-020	{"request_cursor":"","next_cursor":"page+/=2","done":false,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"UNRELATED-WITHDRAWAL\\"}],\\"next_cursor\\":\\"page+/=2\\"}"}	\\xe83b7b054e51c5d5479bde9f2d8985310802327f1a0d0755d351a45dba864a85
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-scan-021	{"request_cursor":"page+/=2","next_cursor":"","done":true,"response":"{\\"withdrawals\\":[{\\"withdrawal_id\\":\\"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx\\",\\"method_id\\":\\"11111111-2222-3333-4444-555555555555\\",\\"address_id\\":\\"AB7J4FF-BGM7G-V2JMIH\\",\\"amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"status\\":\\"success\\",\\"onchain_transaction\\":\\"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6\\"}]}"}	\\x2d631a37fe3a5a37cdca3b5219d3c90a9a95344c7ba245a4887621d56ed37002
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status	{"withdrawals":[{"withdrawal_id":"FTABCDE-xxxxxxxxxxxxxxxxxxxxxx","method_id":"11111111-2222-3333-4444-555555555555","address_id":"AB7J4FF-BGM7G-V2JMIH","amount":{"asset":{"class":"currency","name":"USDC"},"amount":"49.699202"},"fee":{"asset":{"class":"currency","name":"USDC"},"amount":"0.1"},"status":"success","onchain_transaction":"59EoAsLQbK44FPDU9x9mokU4Y7wm6HBE75LWMc1BTHqZkP53iPsvgYBBd2kPqsAFmw57DhnRYDKogtmpnL14jxL6"}]}	\\x938ac8c19089c68d39fc9b783e0006ee2c57ab268a181fe0ef71209f0bd3a292
\.


--
-- Data for Name: issuer_btc_conversion_deferrals; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_deferrals (batch_id, bucket, profile_hash, reason, observed_at) FROM stdin;
\.


--
-- Data for Name: issuer_btc_conversion_drafts; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_drafts (intent_id, kind, revision, observed_at, body, body_sha256) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	order	5	1792687484	{"minimum_output_usdc":"49500000","minimum_gross_usdc":"49699399","limit_price_micros":"99600000000","reference_price_micros":"100000000000","reference_at":"1792687483"}	\\xdc9c2377d9f82aa7c1101e7afddc2311a89b5c74b0968de77c383a836c33a1f8
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal	9	1792687484	{"response":"{\\"gross_amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.799202\\"},\\"net_amount\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"49.699202\\"},\\"fee\\":{\\"asset\\":{\\"class\\":\\"currency\\",\\"name\\":\\"USDC\\"},\\"amount\\":\\"0.1\\"},\\"withdrawal_fee_token\\":\\"exact-owned-fee\\"}"}	\\x3a33dd8851341a61d375a7cb71a301e0cd75b5daed344a9beab9cabfaca6e22c
\.


--
-- Data for Name: issuer_btc_conversion_intents; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_intents (intent_id, batch_id, bucket, profile_hash, treasury_config_hash, policy_version, policy_hash, membership_hash, backend_hash, source_msat, invoice_msat, trade_sats, provider_btc_reserve_msat, routing_fee_limit_msat, dust_msat, minimum_output_usdc, minimum_gross_usdc, limit_price_micros, reference_price_micros, reference_at, reserved_at, stage, revision, order_draft_revision, withdrawal_draft_revision, invoice_hash, order_id, withdrawal_id, provider_credit_status) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	1	0	\\x50fdd9168e707d1db32953bcc3a404ae8f14f675cd48f0a6169b0cfe04477b49	\\x393d0aec7f681d88d6c587bce010c0b6ad237ac39db838895f51eab1605b7402	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9	\\x5d1c89b2efbee4ee91e5c63b396f349acd1cd5fbb629af64bc12568901dbef47	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	50000000	49999000	49899	100000	1000	0	49500000	49699399	99600000000	100000000000	1792687483	1792687483	arrived	12	5	9	\\x7caf1cd4464d7a2d853798caca6eeb3199ab45855f670a709badf651065b385e	ORDER-1	FTABCDE-xxxxxxxxxxxxxxxxxxxxxx	not-independently-proven
\.


--
-- Data for Name: issuer_btc_conversion_output_uses; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_output_uses (intent_id, bucket, operation_id, receipt_hash, released, expiry_receipt) FROM stdin;
\.


--
-- Data for Name: issuer_btc_conversion_outputs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_outputs (intent_id, mint, owner, custody, amount, transaction_signature, receipt) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	\\xc02678f74eeff135b33a2d478be5acc39c184fd350fc39a4c612d2fba09c5eaa	\\x2098a74e4f3c873c48ac5965db333fd446bf186f4d238f6dc729bb369a8e8bdf	\\x3d723c60a5af4f34b42f08098d2a2779b32bbfdf5af251104c1e868db130ebd9	49699202	\\xcf2c0915d41ade02f8043e9fcaa2e1ab3a6c7dfefd0eebf1d43c146ae1ed60086bbab9d0bee208f396043bb0a9ad0c0760f6c42d114243dd1c763806bbf6a30f	\\x4d4342325bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee50fdd9168e707d1db32953bcc3a404ae8f14f675cd48f0a6169b0cfe04477b49cf2c0915d41ade02f8043e9fcaa2e1ab3a6c7dfefd0eebf1d43c146ae1ed60086bbab9d0bee208f396043bb0a9ad0c0760f6c42d114243dd1c763806bbf6a30fa7bf25442cbbe4523dfd704d877bb08f9188cf7b2f2f2e1bddfe12c2225fcb49e8030000000000008259f60200000000c02678f74eeff135b33a2d478be5acc39c184fd350fc39a4c612d2fba09c5eaa2098a74e4f3c873c48ac5965db333fd446bf186f4d238f6dc729bb369a8e8bdf3d723c60a5af4f34b42f08098d2a2779b32bbfdf5af251104c1e868db130ebd9f76e9d9b0447fd947934dede398787f3e74326d1fd0e8f62a0eb6fcae4c99459dc9c2377d9f82aa7c1101e7afddc2311a89b5c74b0968de77c383a836c33a1f8
\.


--
-- Data for Name: issuer_btc_conversion_requests; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_requests (intent_id, kind, method, path, nonce, content_type, body, signature, created_at) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	methods-1792687483796	GET	/funding/v1/methods/withdraw?asset%5Bclass%5D=currency&asset%5Bname%5D=USDC	1792687483796	application/json		BiUFb9lb62Pvye1lJDIqHvy7cEFR4uRf5a37KeiIWVf9xxto6p0vS62NhwnqmMfEDwk83Mwj3ePL+MyCeibDzw==	1792687483
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	address-1792687483801	GET	/funding/v1/addresses?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555	1792687483801	application/json		hjnVBcoNKJbToJBnyfgeJSeBvkAoMB0uHrgfhyjNpeIF6fp7N3UHHLG9f+FDhM+uO/rc3SJ4OqYysTtfPzt+KQ==	1792687483
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	invoice	POST	/0/private/DepositAddresses	1792687483804	application/x-www-form-urlencoded	nonce=1792687483804&asset=XBT&aclass=currency&method=Bitcoin+Lightning&new=true&amount=0.00049999	ugJ++IfEss+/OxpTYTDusf3zfDuNe2EvRPdMWeOZB3vVgITWDU9cm+oSfDdic86gQV2txOuOhQjzfeyLq02L4g==	1792687483
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	order	POST	/0/private/AddOrder	1792687484227	application/x-www-form-urlencoded	nonce=1792687484227&pair=XBTUSDC&type=sell&ordertype=limit&timeinforce=FOK&oflags=fciq&volume=0.00049899&price=99600&cl_ord_id=36f0a33b5a1b474a680bd236a4f65e13	mEMQcZhKfZ+ELUFACZwKQ1hxN8ciLMrQYwx/mwGXP1+VAFDoyUsGPrv3LbmbdsNAtpn4UJSfl1Quy3jx0o+PNw==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	order-status-1792687484260	POST	/0/private/QueryOrders	1792687484260	application/x-www-form-urlencoded	nonce=1792687484260&txid=ORDER-1&trades=true	jAkZnU2ozHNzGOKNcEjD7AtFiVdnyB+tBfxmCoX8mg66euQ7AvdhlK+dVLSSH1N2t1kpKYBxbjdCa5QS4v1i4A==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	trades-1792687484267	POST	/0/private/QueryTrades	1792687484267	application/x-www-form-urlencoded	nonce=1792687484267&txid=TRADE-1&ledgers=true	a/Wukpx1+JQ4vTo8PpwSnzOAWX3AnKrdz+dvgedi/ze42V4wLF9FbcAtZ5DwotzM+8PSbx4uzUnv2J03o7uFHg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	ledgers-1792687484269	POST	/0/private/QueryLedgers	1792687484269	application/x-www-form-urlencoded	nonce=1792687484269&id=L-BTC%2CL-USDC	tFNGF8HhSq1UHyuqEp0nkRgwR6DhvXkDOtuSTrY83cgrttLsIoudmTE1FvyC44BS91snCfA2jyyNPE5M8WMwqQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	fee-1792687484309	GET	/funding/v1/fees/11111111-2222-3333-4444-555555555555?amount=49.799202&fee_included=true	1792687484309	application/json		4Q2pRR9lRFZSSJ7C2fSJln5TKQe+LsH4Wts+jM7uVjM+6TE0lafM5H2xA0SUcX6uuKfiTdhO25kYJf6hQHIR0Q==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal	POST	/funding/v1/withdrawals	1792687484347	application/json	{"scope":{"method_id":"11111111-2222-3333-4444-555555555555"},"address_id":"AB7J4FF-BGM7G-V2JMIH","amount":{"asset_amount":{"asset":{"class":"currency","name":"USDC"},"amount":"49.799202"}},"fee":{"quoted_fee":{"token":"exact-owned-fee"},"fee_included":true},"expected_address":"3CF48HwS4araR6dysSKeQu3zrVMZA5Xg9S96egMXVT1x"}	n38meGSu+e1VtVYxA8h9pF+rr6b2Kz3XTBTxQI8c4NzLCSK+HhHOxp5OVC2I/qDYsTkof+yzn6zoTwcN8indWQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484410	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484410	application/json		bN39zt5zt3/4kZu55kLMMqN9ncgo86XLwP3oMDvH+AbatsuAGKbF1p77YqCFhNMGD1OkTWi9gwTd2sRzoS6xQQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484417	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484417	application/json		0SwBzjNkFXPHaTsyIC62T1LZOmxFNCtAFxbWW61P91o/6uRrvxYsI/slhCpjLTPDVzQnp7P68PE12hR5VZviyg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484520	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484520	application/json		scGW+ZPUNE2cvKMdYxr9mk/1YiPJd8BN5tU5C3NHbE7a01Nn7Ucj63hTLZPejeTaHNxjvar+TY7xLcV+pRQMbA==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484552	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484552	application/json		s36/+OGu+FoK621k/cOQp/wcPsttL4xcFX4u2QKX6fkDm4qQUC7DZH78zKxrdF9KwpFED48/mR2jkJk6FagjYQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484558	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484558	application/json		3eMW+XqQL9Fx8U+YxGejJ3d7yEUeTjpq2121LKU3QE+sqE0V6i6jWVPKqnUEP6tU7/4ID5varp3V6qXffkHraQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484588	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484588	application/json		DUXWZ7APCTfrNeYgaYvMaQxYwndvZy5/NaM2I0SlJAhQDhMrGtGMJZgEHVaXdT2WZFP9rPvld8/GBeBdhpsOHA==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484615	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484615	application/json		a2uwDP/EENR9pJjWub9iT0P4OxeYQODyq7I9b0ybVP10c7ukabn/xMR38OJPBL5hDaFTi1iE547eI+60lVaFHQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484621	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484621	application/json		Os0SrqntDDqozxtQBnE8KgjmciCb6RD7Ro0PTZPJqYgnNBi2jWucNzJohLTSFR6fi36j37FEqwmiVMGJaCQx6w==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484624	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D3	1792687484624	application/json		g9Y3iDLzO+CwL9D/6K9HeZ4zAX22Rw8dbnjzLw8pvckzZWEyK2hPKkvwL0INSZu7J9VslAP96vI/wxpJJuwDaA==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484637	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D4	1792687484637	application/json		qcUHUfKisq84//UsxJyHetwYJNxC5ZWwo2qUVgzva/GIvGxciVKlft9LnMiN1M+kiXHX3Qb9Fh/zdnFoEMwtfg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484657	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D5	1792687484657	application/json		p3VpOM4l1VwkPdR7/utAQOfHsRrIB9JVFgj8+vQupys9KSWBaacxNRwV2wiSv322zusyK7JzpdpxHC0MzkTlQQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484663	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D6	1792687484663	application/json		/5OWGQeW0j7ZhBgCEnQ7+zb0X5fI+Zvo7/4kK2H6BO6xBRKXksM3iCrIv9V6A9aSAjhTvBdDwIIvEXimdQNOJw==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484687	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484687	application/json		+cVcLVjhseUgScTfrWf1UX2MW+5t0UvO/N4zolVLNP5wdWuB4VrgS4FL9hE/5NVf0QwO4D3ztyUQxnsilj/Hxw==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484693	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484693	application/json		s1BLmhKhmAiSMFgxsafiohwUziZD+c7klfpaRigcFU4x5yq70tO0QywM9pmhgda37IH7N9VsBwZNzc3TfWewXQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484730	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484730	application/json		6g7JbAvjrs1roN3AcDLv4AUMRJfFQWmSGWxVAjHSzdxdnHuQOLV0Kk59DjjLzL5bYu0DiPckX3S+MclrfZ2n4A==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484736	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484736	application/json		MeIVeuVT535yr3N7MsSEXLDnQXA8T5/pBf+3tHsu8vQaXc7P/Yhj5v/QE14xHu3K/6WDcUQDupJAO2J8yZtmYQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484774	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484774	application/json		IkWpmarAASPZLb1X/3K8PMeTHjVmE4PZLCp1KSjn6xk8LUkzWDIEgxqBhdsRQTZrn8eprb15uMa6c8v6xxtzMA==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484780	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484780	application/json		OjyfAItwoMnNC1zA0kkg1n+IWr5Koro8cBWtexzkTglmKCrWOg09vMrkTIwnii4PTL7m8M7aEr8gyzDu5guTiw==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484820	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484820	application/json		U2hbDGqV3OAJkMK1zkdWnUWXGkitYvsIBKuaYXmCSJVI+XJG2vP4m+HhQ+PwbBBNBPhYj/v1xTQj12iszXWurg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484826	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484826	application/json		czjS3NZKHY02JXGwys0JqlEBt9xdKhnfo0wNdE6PgIT0ZT9diOSSyQByxPdT6Kr3C4ML3m2yk2YVDR9TDu6Zbg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484866	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484866	application/json		U7X9jDyYXLH6wgXvgVNJfT5MbfiPHJB0iwdlKQ0lozGAphz3CCwOIoe/R87ofkk5To06hHB05lrteG+BuhBksw==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484872	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484872	application/json		aRl1Cwtl0p8hv5ZpeRR33THQ3HVJILhrrhYCE8CgmVSJsnZUFtWbrdylKmFih2A2Ov2hfQdFFmvCCenB+uExCg==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484913	GET	/funding/v1/withdrawals?scope%5Bmethod_id%5D=11111111-2222-3333-4444-555555555555&limit=100	1792687484913	application/json		b2nil1X0yPX5zxD3oIj8s40oU1m9YvrxqOGXL2HOnXyR+I+axWj0I/SRMdv+epWAlKRzApVlzwlUQqNRBFCicQ==	1792687484
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	withdrawal-status-1792687484918	GET	/funding/v1/withdrawals?cursor=page%2B%2F%3D2	1792687484918	application/json		xb+wRx/mEEXDwLXqY0KDAXgOnghQPyLa/YOcXcEvAsmUUld9vh5cwJqOvqJKf2e3zQ0q66btutAGGJn5fA5tfQ==	1792687484
\.


--
-- Data for Name: issuer_btc_kraken_nonces; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_kraken_nonces (api_key_hash, value, lease_id, lease_until, observed_at) FROM stdin;
\\xbe526ae2930ad4a9d06b5053a95e1cfdcb9d15d7d6037818527d44755726abf5	1792687484918	\N	0	1792687484918
\.


--
-- Data for Name: issuer_credit_revenue; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_credit_revenue (event_id, quote_id, payment_signature, asset, mint, amount, payment_time, policy_version, policy_hash) FROM stdin;
\.


--
-- Data for Name: issuer_deposit_root; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_deposit_root (singleton, sealed_seed) FROM stdin;
\.


--
-- Data for Name: issuer_keys; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_keys (key_id, epoch, purpose, spki, sealed_private_key, admitted_evidence, quote_public_key, sealed_quote_key) FROM stdin;
\\x3a239fa4458b39a71a30bd7c7bd67a521b9f48f7273bb6509572190b1decdea9	1	1	\\x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111	\\x2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222	\N	\N	\N
\.


--
-- Data for Name: issuer_lightning_quotes; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_lightning_quotes (quote_id, request, key_id, batch_hash, backend_hash, service_key, payment_hash, sealed_preimage, amount_msat, reserved_at, price_observed_at, state, signed_quote, prepared_response, prepared_signature, settled_amount, settled_at, settle_index, next_attempt, cancellation, policy_version, policy_hash) FROM stdin;
\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	\\x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111	\\x3a239fa4458b39a71a30bd7c7bd67a521b9f48f7273bb6509572190b1decdea9	\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	\\x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111	250000000	1	1	0	\N	\N	\N	\N	\N	\N	0	\N	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9
\.


--
-- Data for Name: issuer_lightning_revenue; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_lightning_revenue (quote_id, backend_hash, received_msat, settled_at, policy_version, policy_hash) FROM stdin;
\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	250000000	1792627170	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9
\.


--
-- Data for Name: issuer_lightning_weekly; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_lightning_weekly (batch_id, week, backend_hash, policy_version, policy_hash, amount, witness, burn, operations, carry_before, carry_after, burn_carry_before, burn_carry_after, operations_carry_before, operations_carry_after, reserve_before, reserve_after, membership_hash) FROM stdin;
1	2963	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9	250000000	50000000	75000000	125000000	0	0	0	0	0	0	0	0	\\x5d1c89b2efbee4ee91e5c63b396f349acd1cd5fbb629af64bc12568901dbef47
\.


--
-- Data for Name: issuer_lightning_weekly_events; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_lightning_weekly_events (quote_id, batch_id) FROM stdin;
\\xe6f8a085356606c9fa35657b303bb1fd92c5ebd28cc0a4289f8557c657a4e99a	1
\.


--
-- Data for Name: issuer_payment_observations; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_payment_observations (payment_signature, quote_id, payer, slot, payment_time, amount, wire_sha256, disposition) FROM stdin;
\.


--
-- Data for Name: issuer_quotes; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_quotes (quote_id, quote, key_id, batch_hash, deposit_owner, sealed_deposit_key, price_observed_at, payment_signature, payment_payer, payment_slot, payment_time, payment_amount, issued_response, signed_quote, policy_version, policy_hash) FROM stdin;
\.


--
-- Data for Name: issuer_revenue_policies; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_revenue_policies (policy_version, policy_hash) FROM stdin;
1	\\xe0fc245ad422c7a1b1504fc07f29e427b7d46fce04da2ee5618f3ca39d6093b9
2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9
\.


--
-- Data for Name: issuer_transparency_cursor; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_transparency_cursor (singleton, checkpoint) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_attempts; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_attempts (transaction_signature, movement_id, nonce_address, nonce_value, message, packet, state, finalized_slot, execution_error, fee) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batch_attempts; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batch_attempts (transaction_signature, batch_id, nonce_address, nonce_value, message, packet, state, finalized_slot, execution_error, fee, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batch_costs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batch_costs (transaction_signature, movement_id, fee, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batch_members; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batch_members (movement_id, batch_id, ordinal) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batches; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batches (batch_id, config_hash, member_hash, member_count, state, nonce_address, nonce_value, message, packet, transaction_signature, finalized_slot, execution_error, fee, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_burn_intents; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_burn_intents (intent_id, config_hash, token_program, payer, profile, epoch, cash, carry, instruction, membership_hash, funding_hash, state, finalized_slot, week_frame, close_receipt, expiry_slot, expiry_frame, expiry_receipt) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_burn_liabilities; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_burn_liabilities (batch_id, amount, state, funding_hash, receipt) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_burn_members; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_burn_members (batch_id, intent_id, released) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_funding_jobs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_funding_jobs (batch_id, next_attempt) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_keys; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_keys (service_key, purpose, role, public_key, sealed_key) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_movements; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_movements (movement_id, payment_signature, kind, config_hash, source, destination, destination_owner, amount, ready_at, state, nonce_address, nonce_value, message, packet, transaction_signature, finalized_slot, execution_error, fee, batch_id, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_nonce_lanes; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_nonce_lanes (nonce_address, owner_kind, owner_id) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_observation_jobs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_observation_jobs (config_hash, quote_id, next_attempt) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_rewards_intents; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_rewards_intents (intent_id, batch_id, epoch, pool, funder, source, mint, amount, state, receipt) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_weekly; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_weekly (batch_id, week, asset, cutoff, mint, config_hash, amount, witness, operations, carry_before, carry_after, membership_hash, policy_version, policy_hash, burn, burn_carry_before, burn_carry_after, operations_carry_before, operations_carry_after, reserve_before, reserve_after) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_weekly_events; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_weekly_events (event_id, batch_id) FROM stdin;
\.


--
-- Name: issuer_credit_revenue_event_id_seq; Type: SEQUENCE SET; Schema: public; Owner: andreyyurlov
--

SELECT pg_catalog.setval('public.issuer_credit_revenue_event_id_seq', 1, false);


--
-- Name: issuer_lightning_weekly_batch_id_seq; Type: SEQUENCE SET; Schema: public; Owner: andreyyurlov
--

SELECT pg_catalog.setval('public.issuer_lightning_weekly_batch_id_seq', 1, true);


--
-- Name: issuer_treasury_weekly_batch_id_seq; Type: SEQUENCE SET; Schema: public; Owner: andreyyurlov
--

SELECT pg_catalog.setval('public.issuer_treasury_weekly_batch_id_seq', 1, false);


--
-- Name: issuer_btc_conversion_accounting issuer_btc_conversion_accounting_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_accounting
    ADD CONSTRAINT issuer_btc_conversion_accounting_pkey PRIMARY KEY (intent_id);


--
-- Name: issuer_btc_conversion_artifacts issuer_btc_conversion_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_artifacts
    ADD CONSTRAINT issuer_btc_conversion_artifacts_pkey PRIMARY KEY (intent_id, kind);


--
-- Name: issuer_btc_conversion_deferrals issuer_btc_conversion_deferrals_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_deferrals
    ADD CONSTRAINT issuer_btc_conversion_deferrals_pkey PRIMARY KEY (batch_id, bucket, profile_hash);


--
-- Name: issuer_btc_conversion_drafts issuer_btc_conversion_drafts_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_drafts
    ADD CONSTRAINT issuer_btc_conversion_drafts_pkey PRIMARY KEY (intent_id, kind, revision);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_batch_id_bucket_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_batch_id_bucket_key UNIQUE (batch_id, bucket);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_invoice_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_invoice_hash_key UNIQUE (invoice_hash);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_order_id_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_order_id_key UNIQUE (order_id);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_pkey PRIMARY KEY (intent_id);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_withdrawal_id_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_withdrawal_id_key UNIQUE (withdrawal_id);


--
-- Name: issuer_btc_conversion_output_uses issuer_btc_conversion_output_uses_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_output_uses
    ADD CONSTRAINT issuer_btc_conversion_output_uses_pkey PRIMARY KEY (intent_id, operation_id);


--
-- Name: issuer_btc_conversion_outputs issuer_btc_conversion_outputs_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_outputs
    ADD CONSTRAINT issuer_btc_conversion_outputs_pkey PRIMARY KEY (intent_id);


--
-- Name: issuer_btc_conversion_outputs issuer_btc_conversion_outputs_receipt_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_outputs
    ADD CONSTRAINT issuer_btc_conversion_outputs_receipt_key UNIQUE (receipt);


--
-- Name: issuer_btc_conversion_outputs issuer_btc_conversion_outputs_transaction_signature_custody_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_outputs
    ADD CONSTRAINT issuer_btc_conversion_outputs_transaction_signature_custody_key UNIQUE (transaction_signature, custody);


--
-- Name: issuer_btc_conversion_requests issuer_btc_conversion_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_requests
    ADD CONSTRAINT issuer_btc_conversion_requests_pkey PRIMARY KEY (intent_id, kind);


--
-- Name: issuer_btc_kraken_nonces issuer_btc_kraken_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_kraken_nonces
    ADD CONSTRAINT issuer_btc_kraken_nonces_pkey PRIMARY KEY (api_key_hash);


--
-- Name: issuer_credit_revenue issuer_credit_revenue_payment_signature_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue
    ADD CONSTRAINT issuer_credit_revenue_payment_signature_key UNIQUE (payment_signature);


--
-- Name: issuer_credit_revenue issuer_credit_revenue_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue
    ADD CONSTRAINT issuer_credit_revenue_pkey PRIMARY KEY (event_id);


--
-- Name: issuer_credit_revenue issuer_credit_revenue_quote_id_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue
    ADD CONSTRAINT issuer_credit_revenue_quote_id_key UNIQUE (quote_id);


--
-- Name: issuer_deposit_root issuer_deposit_root_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_deposit_root
    ADD CONSTRAINT issuer_deposit_root_pkey PRIMARY KEY (singleton);


--
-- Name: issuer_keys issuer_keys_epoch_purpose_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_keys
    ADD CONSTRAINT issuer_keys_epoch_purpose_key UNIQUE (epoch, purpose);


--
-- Name: issuer_keys issuer_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_keys
    ADD CONSTRAINT issuer_keys_pkey PRIMARY KEY (key_id);


--
-- Name: issuer_keys issuer_keys_spki_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_keys
    ADD CONSTRAINT issuer_keys_spki_key UNIQUE (spki);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_backend_hash_settle_index_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_backend_hash_settle_index_key UNIQUE (backend_hash, settle_index);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_key_id_batch_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_key_id_batch_hash_key UNIQUE (key_id, batch_hash);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_payment_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_payment_hash_key UNIQUE (payment_hash);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_pkey PRIMARY KEY (quote_id);


--
-- Name: issuer_lightning_revenue issuer_lightning_revenue_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_revenue
    ADD CONSTRAINT issuer_lightning_revenue_pkey PRIMARY KEY (quote_id);


--
-- Name: issuer_lightning_weekly issuer_lightning_weekly_backend_hash_week_policy_version_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly
    ADD CONSTRAINT issuer_lightning_weekly_backend_hash_week_policy_version_key UNIQUE (backend_hash, week, policy_version);


--
-- Name: issuer_lightning_weekly_events issuer_lightning_weekly_events_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly_events
    ADD CONSTRAINT issuer_lightning_weekly_events_pkey PRIMARY KEY (quote_id);


--
-- Name: issuer_lightning_weekly issuer_lightning_weekly_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly
    ADD CONSTRAINT issuer_lightning_weekly_pkey PRIMARY KEY (batch_id);


--
-- Name: issuer_treasury_movements issuer_move_batch_pair; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_movements
    ADD CONSTRAINT issuer_move_batch_pair UNIQUE (movement_id, batch_id);


--
-- Name: issuer_payment_observations issuer_payment_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_payment_observations
    ADD CONSTRAINT issuer_payment_observations_pkey PRIMARY KEY (payment_signature);


--
-- Name: issuer_quotes issuer_quotes_deposit_owner_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_deposit_owner_key UNIQUE (deposit_owner);


--
-- Name: issuer_quotes issuer_quotes_key_id_batch_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_key_id_batch_hash_key UNIQUE (key_id, batch_hash);


--
-- Name: issuer_quotes issuer_quotes_payment_signature_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_payment_signature_key UNIQUE (payment_signature);


--
-- Name: issuer_quotes issuer_quotes_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_pkey PRIMARY KEY (quote_id);


--
-- Name: issuer_revenue_policies issuer_revenue_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_revenue_policies
    ADD CONSTRAINT issuer_revenue_policies_pkey PRIMARY KEY (policy_version);


--
-- Name: issuer_revenue_policies issuer_revenue_policies_policy_version_policy_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_revenue_policies
    ADD CONSTRAINT issuer_revenue_policies_policy_version_policy_hash_key UNIQUE (policy_version, policy_hash);


--
-- Name: issuer_transparency_cursor issuer_transparency_cursor_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_transparency_cursor
    ADD CONSTRAINT issuer_transparency_cursor_pkey PRIMARY KEY (singleton);


--
-- Name: issuer_treasury_attempts issuer_treasury_attempts_movement_id_nonce_address_nonce_va_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_attempts
    ADD CONSTRAINT issuer_treasury_attempts_movement_id_nonce_address_nonce_va_key UNIQUE (movement_id, nonce_address, nonce_value);


--
-- Name: issuer_treasury_attempts issuer_treasury_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_attempts
    ADD CONSTRAINT issuer_treasury_attempts_pkey PRIMARY KEY (transaction_signature);


--
-- Name: issuer_treasury_batch_attempts issuer_treasury_batch_attempt_batch_id_nonce_address_nonce__key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_attempts
    ADD CONSTRAINT issuer_treasury_batch_attempt_batch_id_nonce_address_nonce__key UNIQUE (batch_id, nonce_address, nonce_value);


--
-- Name: issuer_treasury_batch_attempts issuer_treasury_batch_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_attempts
    ADD CONSTRAINT issuer_treasury_batch_attempts_pkey PRIMARY KEY (transaction_signature);


--
-- Name: issuer_treasury_batch_costs issuer_treasury_batch_costs_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_costs
    ADD CONSTRAINT issuer_treasury_batch_costs_pkey PRIMARY KEY (transaction_signature, movement_id);


--
-- Name: issuer_treasury_batch_members issuer_treasury_batch_members_batch_id_ordinal_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_members
    ADD CONSTRAINT issuer_treasury_batch_members_batch_id_ordinal_key UNIQUE (batch_id, ordinal);


--
-- Name: issuer_treasury_batch_members issuer_treasury_batch_members_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_members
    ADD CONSTRAINT issuer_treasury_batch_members_pkey PRIMARY KEY (movement_id);


--
-- Name: issuer_treasury_batches issuer_treasury_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batches
    ADD CONSTRAINT issuer_treasury_batches_pkey PRIMARY KEY (batch_id);


--
-- Name: issuer_treasury_batches issuer_treasury_batches_transaction_signature_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batches
    ADD CONSTRAINT issuer_treasury_batches_transaction_signature_key UNIQUE (transaction_signature);


--
-- Name: issuer_treasury_burn_intents issuer_treasury_burn_intents_funding_hash_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_intents
    ADD CONSTRAINT issuer_treasury_burn_intents_funding_hash_key UNIQUE (funding_hash);


--
-- Name: issuer_treasury_burn_intents issuer_treasury_burn_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_intents
    ADD CONSTRAINT issuer_treasury_burn_intents_pkey PRIMARY KEY (intent_id);


--
-- Name: issuer_treasury_burn_intents issuer_treasury_burn_intents_token_program_epoch_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_intents
    ADD CONSTRAINT issuer_treasury_burn_intents_token_program_epoch_key UNIQUE (token_program, epoch);


--
-- Name: issuer_treasury_burn_liabilities issuer_treasury_burn_liabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_liabilities
    ADD CONSTRAINT issuer_treasury_burn_liabilities_pkey PRIMARY KEY (batch_id);


--
-- Name: issuer_treasury_burn_members issuer_treasury_burn_members_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_members
    ADD CONSTRAINT issuer_treasury_burn_members_pkey PRIMARY KEY (intent_id, batch_id);


--
-- Name: issuer_treasury_funding_jobs issuer_treasury_funding_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_funding_jobs
    ADD CONSTRAINT issuer_treasury_funding_jobs_pkey PRIMARY KEY (batch_id);


--
-- Name: issuer_treasury_keys issuer_treasury_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_keys
    ADD CONSTRAINT issuer_treasury_keys_pkey PRIMARY KEY (service_key, purpose, role);


--
-- Name: issuer_treasury_keys issuer_treasury_keys_public_key_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_keys
    ADD CONSTRAINT issuer_treasury_keys_public_key_key UNIQUE (public_key);


--
-- Name: issuer_treasury_movements issuer_treasury_movements_payment_signature_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_movements
    ADD CONSTRAINT issuer_treasury_movements_payment_signature_key UNIQUE (payment_signature);


--
-- Name: issuer_treasury_movements issuer_treasury_movements_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_movements
    ADD CONSTRAINT issuer_treasury_movements_pkey PRIMARY KEY (movement_id);


--
-- Name: issuer_treasury_nonce_lanes issuer_treasury_nonce_lanes_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_nonce_lanes
    ADD CONSTRAINT issuer_treasury_nonce_lanes_pkey PRIMARY KEY (nonce_address);


--
-- Name: issuer_treasury_observation_jobs issuer_treasury_observation_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_observation_jobs
    ADD CONSTRAINT issuer_treasury_observation_jobs_pkey PRIMARY KEY (config_hash, quote_id);


--
-- Name: issuer_treasury_rewards_intents issuer_treasury_rewards_intents_batch_id_epoch_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_rewards_intents
    ADD CONSTRAINT issuer_treasury_rewards_intents_batch_id_epoch_key UNIQUE (batch_id, epoch);


--
-- Name: issuer_treasury_rewards_intents issuer_treasury_rewards_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_rewards_intents
    ADD CONSTRAINT issuer_treasury_rewards_intents_pkey PRIMARY KEY (intent_id);


--
-- Name: issuer_treasury_weekly_events issuer_treasury_weekly_events_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly_events
    ADD CONSTRAINT issuer_treasury_weekly_events_pkey PRIMARY KEY (event_id);


--
-- Name: issuer_treasury_weekly issuer_treasury_weekly_pkey; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly
    ADD CONSTRAINT issuer_treasury_weekly_pkey PRIMARY KEY (batch_id);


--
-- Name: issuer_treasury_weekly issuer_treasury_weekly_week_asset_policy_version_key; Type: CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly
    ADD CONSTRAINT issuer_treasury_weekly_week_asset_policy_version_key UNIQUE (week, asset, policy_version);


--
-- Name: issuer_btc_output_active_use; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE UNIQUE INDEX issuer_btc_output_active_use ON public.issuer_btc_conversion_output_uses USING btree (intent_id) WHERE (NOT released);


--
-- Name: issuer_burn_active_member; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE UNIQUE INDEX issuer_burn_active_member ON public.issuer_treasury_burn_members USING btree (batch_id) WHERE (NOT released);


--
-- Name: issuer_lightning_prepared_queue; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE INDEX issuer_lightning_prepared_queue ON public.issuer_lightning_quotes USING btree (backend_hash, service_key, next_attempt, quote_id) WHERE (state = 2);


--
-- Name: issuer_payment_observations_quote; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE INDEX issuer_payment_observations_quote ON public.issuer_payment_observations USING btree (quote_id);


--
-- Name: issuer_treasury_active_nonce; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE UNIQUE INDEX issuer_treasury_active_nonce ON public.issuer_treasury_movements USING btree (nonce_address) WHERE ((batch_id IS NULL) AND (nonce_address IS NOT NULL) AND (state = ANY (ARRAY[0, 1, 4])));


--
-- Name: issuer_treasury_pending_batches; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE INDEX issuer_treasury_pending_batches ON public.issuer_treasury_batches USING btree (config_hash, batch_id) WHERE (state = ANY (ARRAY[0, 1, 4]));


--
-- Name: issuer_treasury_ready_movements; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE INDEX issuer_treasury_ready_movements ON public.issuer_treasury_movements USING btree (config_hash, ready_at, movement_id) WHERE ((state = 0) AND (batch_id IS NULL) AND (message IS NULL));


--
-- Name: issuer_treasury_rewards_active; Type: INDEX; Schema: public; Owner: andreyyurlov
--

CREATE UNIQUE INDEX issuer_treasury_rewards_active ON public.issuer_treasury_rewards_intents USING btree (batch_id) WHERE (state = ANY (ARRAY[0, 1]));


--
-- Name: issuer_btc_conversion_accounting issuer_btc_accounting_binding; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_accounting_binding BEFORE INSERT ON public.issuer_btc_conversion_accounting FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_accounting_binding();


--
-- Name: issuer_btc_conversion_accounting issuer_btc_accounting_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_accounting_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_accounting FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_artifacts issuer_btc_artifact_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_artifact_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_artifacts FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_source; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_conversion_source BEFORE INSERT ON public.issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_conversion_source();


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_transition; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_conversion_transition BEFORE UPDATE ON public.issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_conversion_transition();


--
-- Name: issuer_btc_conversion_drafts issuer_btc_draft_admission; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_draft_admission BEFORE INSERT ON public.issuer_btc_conversion_drafts FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_draft_admission();


--
-- Name: issuer_btc_conversion_drafts issuer_btc_draft_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_draft_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_drafts FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_intents issuer_btc_intent_no_delete; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_intent_no_delete BEFORE DELETE ON public.issuer_btc_conversion_intents FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_outputs issuer_btc_output_admission; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_output_admission BEFORE INSERT ON public.issuer_btc_conversion_outputs FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_output_admission();


--
-- Name: issuer_btc_conversion_outputs issuer_btc_output_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_output_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_outputs FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_output_uses issuer_btc_output_use_binding; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_output_use_binding BEFORE INSERT ON public.issuer_btc_conversion_output_uses FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_output_use_binding();


--
-- Name: issuer_btc_conversion_requests issuer_btc_request_capacity; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_request_capacity BEFORE INSERT ON public.issuer_btc_conversion_requests FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_request_capacity();


--
-- Name: issuer_btc_conversion_requests issuer_btc_request_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_request_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_requests FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_artifact_immutable();


--
-- Name: issuer_btc_conversion_output_uses issuer_btc_use_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_btc_use_immutable BEFORE DELETE OR UPDATE ON public.issuer_btc_conversion_output_uses FOR EACH ROW EXECUTE FUNCTION public.issuer_btc_output_release();


--
-- Name: issuer_treasury_burn_intents issuer_burn_intent_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_burn_intent_immutable BEFORE UPDATE ON public.issuer_treasury_burn_intents FOR EACH ROW EXECUTE FUNCTION public.issuer_burn_intent_immutable();


--
-- Name: issuer_treasury_burn_liabilities issuer_burn_liability_binding; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_burn_liability_binding BEFORE INSERT OR UPDATE ON public.issuer_treasury_burn_liabilities FOR EACH ROW EXECUTE FUNCTION public.issuer_burn_liability_binding();


--
-- Name: issuer_treasury_burn_members issuer_burn_member_binding; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_burn_member_binding BEFORE INSERT ON public.issuer_treasury_burn_members FOR EACH ROW EXECUTE FUNCTION public.issuer_burn_member_binding();


--
-- Name: issuer_treasury_burn_members issuer_burn_member_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_burn_member_immutable BEFORE DELETE OR UPDATE ON public.issuer_treasury_burn_members FOR EACH ROW EXECUTE FUNCTION public.issuer_burn_member_immutable();


--
-- Name: issuer_credit_revenue issuer_credit_revenue_parent; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_credit_revenue_parent BEFORE INSERT OR UPDATE ON public.issuer_credit_revenue FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_parent_policy();


--
-- Name: issuer_credit_revenue issuer_credit_revenue_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_credit_revenue_policy_immutable BEFORE UPDATE ON public.issuer_credit_revenue FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_lightning_quotes_policy_immutable BEFORE UPDATE ON public.issuer_lightning_quotes FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_lightning_revenue issuer_lightning_revenue_parent; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_lightning_revenue_parent BEFORE INSERT OR UPDATE ON public.issuer_lightning_revenue FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_parent_policy();


--
-- Name: issuer_lightning_revenue issuer_lightning_revenue_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_lightning_revenue_policy_immutable BEFORE UPDATE ON public.issuer_lightning_revenue FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_lightning_weekly_events issuer_lightning_week_member_policy; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_lightning_week_member_policy BEFORE INSERT OR UPDATE ON public.issuer_lightning_weekly_events FOR EACH ROW EXECUTE FUNCTION public.issuer_lightning_week_member_policy();


--
-- Name: issuer_lightning_weekly issuer_lightning_weekly_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_lightning_weekly_policy_immutable BEFORE UPDATE ON public.issuer_lightning_weekly FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_quotes issuer_quotes_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_quotes_policy_immutable BEFORE UPDATE ON public.issuer_quotes FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_revenue_policies issuer_revenue_policies_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_revenue_policies_immutable BEFORE DELETE OR UPDATE ON public.issuer_revenue_policies FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_treasury_weekly issuer_treasury_weekly_policy_immutable; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_treasury_weekly_policy_immutable BEFORE UPDATE ON public.issuer_treasury_weekly FOR EACH ROW EXECUTE FUNCTION public.issuer_revenue_policy_immutable();


--
-- Name: issuer_treasury_weekly_events issuer_weekly_member_policy; Type: TRIGGER; Schema: public; Owner: andreyyurlov
--

CREATE TRIGGER issuer_weekly_member_policy BEFORE INSERT OR UPDATE ON public.issuer_treasury_weekly_events FOR EACH ROW EXECUTE FUNCTION public.issuer_weekly_member_policy();


--
-- Name: issuer_btc_conversion_accounting issuer_btc_conversion_accounting_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_accounting
    ADD CONSTRAINT issuer_btc_conversion_accounting_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_intents(intent_id);


--
-- Name: issuer_btc_conversion_artifacts issuer_btc_conversion_artifacts_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_artifacts
    ADD CONSTRAINT issuer_btc_conversion_artifacts_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_intents(intent_id);


--
-- Name: issuer_btc_conversion_deferrals issuer_btc_conversion_deferrals_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_deferrals
    ADD CONSTRAINT issuer_btc_conversion_deferrals_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_lightning_weekly(batch_id);


--
-- Name: issuer_btc_conversion_drafts issuer_btc_conversion_drafts_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_drafts
    ADD CONSTRAINT issuer_btc_conversion_drafts_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_intents(intent_id);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_lightning_weekly(batch_id);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_intent_id_order_draft_kind_o_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_intent_id_order_draft_kind_o_fkey FOREIGN KEY (intent_id, order_draft_kind, order_draft_revision) REFERENCES public.issuer_btc_conversion_drafts(intent_id, kind, revision);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_intent_id_withdrawal_draft_k_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_intent_id_withdrawal_draft_k_fkey FOREIGN KEY (intent_id, withdrawal_draft_kind, withdrawal_draft_revision) REFERENCES public.issuer_btc_conversion_drafts(intent_id, kind, revision);


--
-- Name: issuer_btc_conversion_intents issuer_btc_conversion_intents_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_intents
    ADD CONSTRAINT issuer_btc_conversion_intents_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_btc_conversion_output_uses issuer_btc_conversion_output_uses_burn_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_output_uses
    ADD CONSTRAINT issuer_btc_conversion_output_uses_burn_intent_id_fkey FOREIGN KEY (burn_intent_id) REFERENCES public.issuer_treasury_burn_intents(intent_id);


--
-- Name: issuer_btc_conversion_output_uses issuer_btc_conversion_output_uses_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_output_uses
    ADD CONSTRAINT issuer_btc_conversion_output_uses_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_outputs(intent_id);


--
-- Name: issuer_btc_conversion_outputs issuer_btc_conversion_outputs_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_outputs
    ADD CONSTRAINT issuer_btc_conversion_outputs_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_intents(intent_id);


--
-- Name: issuer_btc_conversion_requests issuer_btc_conversion_requests_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_btc_conversion_requests
    ADD CONSTRAINT issuer_btc_conversion_requests_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_btc_conversion_intents(intent_id);


--
-- Name: issuer_credit_revenue issuer_credit_revenue_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue
    ADD CONSTRAINT issuer_credit_revenue_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_credit_revenue issuer_credit_revenue_quote_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_credit_revenue
    ADD CONSTRAINT issuer_credit_revenue_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES public.issuer_quotes(quote_id);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.issuer_keys(key_id);


--
-- Name: issuer_lightning_quotes issuer_lightning_quotes_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_quotes
    ADD CONSTRAINT issuer_lightning_quotes_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_lightning_revenue issuer_lightning_revenue_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_revenue
    ADD CONSTRAINT issuer_lightning_revenue_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_lightning_revenue issuer_lightning_revenue_quote_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_revenue
    ADD CONSTRAINT issuer_lightning_revenue_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES public.issuer_lightning_quotes(quote_id);


--
-- Name: issuer_lightning_weekly_events issuer_lightning_weekly_events_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly_events
    ADD CONSTRAINT issuer_lightning_weekly_events_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_lightning_weekly(batch_id);


--
-- Name: issuer_lightning_weekly_events issuer_lightning_weekly_events_quote_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly_events
    ADD CONSTRAINT issuer_lightning_weekly_events_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES public.issuer_lightning_revenue(quote_id);


--
-- Name: issuer_lightning_weekly issuer_lightning_weekly_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_lightning_weekly
    ADD CONSTRAINT issuer_lightning_weekly_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_payment_observations issuer_payment_observations_quote_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_payment_observations
    ADD CONSTRAINT issuer_payment_observations_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES public.issuer_quotes(quote_id);


--
-- Name: issuer_quotes issuer_quotes_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_key_id_fkey FOREIGN KEY (key_id) REFERENCES public.issuer_keys(key_id);


--
-- Name: issuer_quotes issuer_quotes_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_quotes
    ADD CONSTRAINT issuer_quotes_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: issuer_treasury_attempts issuer_treasury_attempts_movement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_attempts
    ADD CONSTRAINT issuer_treasury_attempts_movement_id_fkey FOREIGN KEY (movement_id) REFERENCES public.issuer_treasury_movements(movement_id);


--
-- Name: issuer_treasury_batch_attempts issuer_treasury_batch_attempts_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_attempts
    ADD CONSTRAINT issuer_treasury_batch_attempts_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_batches(batch_id);


--
-- Name: issuer_treasury_batch_costs issuer_treasury_batch_costs_movement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_costs
    ADD CONSTRAINT issuer_treasury_batch_costs_movement_id_fkey FOREIGN KEY (movement_id) REFERENCES public.issuer_treasury_batch_members(movement_id);


--
-- Name: issuer_treasury_batch_costs issuer_treasury_batch_costs_transaction_signature_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_costs
    ADD CONSTRAINT issuer_treasury_batch_costs_transaction_signature_fkey FOREIGN KEY (transaction_signature) REFERENCES public.issuer_treasury_batch_attempts(transaction_signature);


--
-- Name: issuer_treasury_batch_members issuer_treasury_batch_members_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_members
    ADD CONSTRAINT issuer_treasury_batch_members_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_batches(batch_id);


--
-- Name: issuer_treasury_batch_members issuer_treasury_batch_members_movement_id_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_batch_members
    ADD CONSTRAINT issuer_treasury_batch_members_movement_id_batch_id_fkey FOREIGN KEY (movement_id, batch_id) REFERENCES public.issuer_treasury_movements(movement_id, batch_id);


--
-- Name: issuer_treasury_burn_liabilities issuer_treasury_burn_liabilities_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_liabilities
    ADD CONSTRAINT issuer_treasury_burn_liabilities_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_weekly(batch_id);


--
-- Name: issuer_treasury_burn_members issuer_treasury_burn_members_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_members
    ADD CONSTRAINT issuer_treasury_burn_members_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_burn_liabilities(batch_id);


--
-- Name: issuer_treasury_burn_members issuer_treasury_burn_members_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_burn_members
    ADD CONSTRAINT issuer_treasury_burn_members_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.issuer_treasury_burn_intents(intent_id);


--
-- Name: issuer_treasury_funding_jobs issuer_treasury_funding_jobs_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_funding_jobs
    ADD CONSTRAINT issuer_treasury_funding_jobs_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_weekly(batch_id);


--
-- Name: issuer_treasury_movements issuer_treasury_movements_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_movements
    ADD CONSTRAINT issuer_treasury_movements_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_batches(batch_id);


--
-- Name: issuer_treasury_movements issuer_treasury_movements_payment_signature_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_movements
    ADD CONSTRAINT issuer_treasury_movements_payment_signature_fkey FOREIGN KEY (payment_signature) REFERENCES public.issuer_payment_observations(payment_signature);


--
-- Name: issuer_treasury_observation_jobs issuer_treasury_observation_jobs_quote_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_observation_jobs
    ADD CONSTRAINT issuer_treasury_observation_jobs_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES public.issuer_quotes(quote_id);


--
-- Name: issuer_treasury_rewards_intents issuer_treasury_rewards_intents_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_rewards_intents
    ADD CONSTRAINT issuer_treasury_rewards_intents_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_weekly(batch_id);


--
-- Name: issuer_treasury_weekly_events issuer_treasury_weekly_events_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly_events
    ADD CONSTRAINT issuer_treasury_weekly_events_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.issuer_treasury_weekly(batch_id);


--
-- Name: issuer_treasury_weekly_events issuer_treasury_weekly_events_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly_events
    ADD CONSTRAINT issuer_treasury_weekly_events_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.issuer_credit_revenue(event_id);


--
-- Name: issuer_treasury_weekly issuer_treasury_weekly_policy_version_policy_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: andreyyurlov
--

ALTER TABLE ONLY public.issuer_treasury_weekly
    ADD CONSTRAINT issuer_treasury_weekly_policy_version_policy_hash_fkey FOREIGN KEY (policy_version, policy_hash) REFERENCES public.issuer_revenue_policies(policy_version, policy_hash);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: andreyyurlov
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;


--
-- PostgreSQL database dump complete
--

\unrestrict MgsbpzUZ6c09PdfJUcMqtL6eT9icYi8o2yI9eB5bqTv3Ew1yBHKNbdUdMypg3mh

