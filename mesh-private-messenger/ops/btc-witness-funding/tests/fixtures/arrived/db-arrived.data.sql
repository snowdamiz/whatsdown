--
-- PostgreSQL database dump
--

\restrict cN5PGhsoufv9KzbYL7Ei1cUryfym7bSY9eWlzttTZkHeUFpVCVuitYFMMLjlA3B

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
-- Data for Name: issuer_revenue_policies; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_revenue_policies (policy_version, policy_hash) FROM stdin;
1	\\xe0fc245ad422c7a1b1504fc07f29e427b7d46fce04da2ee5618f3ca39d6093b9
2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9
\.


--
-- Data for Name: issuer_lightning_weekly; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_lightning_weekly (batch_id, week, backend_hash, policy_version, policy_hash, amount, witness, burn, operations, carry_before, carry_after, burn_carry_before, burn_carry_after, operations_carry_before, operations_carry_after, reserve_before, reserve_after, membership_hash) FROM stdin;
1	2963	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9	250000000	50000000	75000000	125000000	0	0	0	0	0	0	0	0	\\x5d1c89b2efbee4ee91e5c63b396f349acd1cd5fbb629af64bc12568901dbef47
\.


--
-- Data for Name: issuer_btc_conversion_intents; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_intents (intent_id, batch_id, bucket, profile_hash, treasury_config_hash, policy_version, policy_hash, membership_hash, backend_hash, source_msat, invoice_msat, trade_sats, provider_btc_reserve_msat, routing_fee_limit_msat, dust_msat, minimum_output_usdc, minimum_gross_usdc, limit_price_micros, reference_price_micros, reference_at, reserved_at, stage, revision, order_draft_revision, withdrawal_draft_revision, invoice_hash, order_id, withdrawal_id, provider_credit_status) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	1	0	\\x50fdd9168e707d1db32953bcc3a404ae8f14f675cd48f0a6169b0cfe04477b49	\\x393d0aec7f681d88d6c587bce010c0b6ad237ac39db838895f51eab1605b7402	2	\\xc1d54934a091845ddcfe7e8bc71d1dc15120af97a9761666a822cd21ceac58a9	\\x5d1c89b2efbee4ee91e5c63b396f349acd1cd5fbb629af64bc12568901dbef47	\\x8af08fab2b7b3cf407af3560dd3bd5d8e7e5edb550916c2236dcbaf77faaddd7	50000000	49999000	49899	100000	1000	0	49500000	49699399	99600000000	100000000000	1792687483	1792687483	arrived	12	5	9	\\x7caf1cd4464d7a2d853798caca6eeb3199ab45855f670a709badf651065b385e	ORDER-1	FTABCDE-xxxxxxxxxxxxxxxxxxxxxx	not-independently-proven
\.


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
-- Data for Name: issuer_btc_conversion_outputs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_outputs (intent_id, mint, owner, custody, amount, transaction_signature, receipt) FROM stdin;
\\x5bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee	\\xc02678f74eeff135b33a2d478be5acc39c184fd350fc39a4c612d2fba09c5eaa	\\x2098a74e4f3c873c48ac5965db333fd446bf186f4d238f6dc729bb369a8e8bdf	\\x3d723c60a5af4f34b42f08098d2a2779b32bbfdf5af251104c1e868db130ebd9	49699202	\\xcf2c0915d41ade02f8043e9fcaa2e1ab3a6c7dfefd0eebf1d43c146ae1ed60086bbab9d0bee208f396043bb0a9ad0c0760f6c42d114243dd1c763806bbf6a30f	\\x4d4342325bfb7695f1f34f4732c4b5152aff5174bd10668f1ab4958cf64d7dc99af539ee50fdd9168e707d1db32953bcc3a404ae8f14f675cd48f0a6169b0cfe04477b49cf2c0915d41ade02f8043e9fcaa2e1ab3a6c7dfefd0eebf1d43c146ae1ed60086bbab9d0bee208f396043bb0a9ad0c0760f6c42d114243dd1c763806bbf6a30fa7bf25442cbbe4523dfd704d877bb08f9188cf7b2f2f2e1bddfe12c2225fcb49e8030000000000008259f60200000000c02678f74eeff135b33a2d478be5acc39c184fd350fc39a4c612d2fba09c5eaa2098a74e4f3c873c48ac5965db333fd446bf186f4d238f6dc729bb369a8e8bdf3d723c60a5af4f34b42f08098d2a2779b32bbfdf5af251104c1e868db130ebd9f76e9d9b0447fd947934dede398787f3e74326d1fd0e8f62a0eb6fcae4c99459dc9c2377d9f82aa7c1101e7afddc2311a89b5c74b0968de77c383a836c33a1f8
\.


--
-- Data for Name: issuer_treasury_burn_intents; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_burn_intents (intent_id, config_hash, token_program, payer, profile, epoch, cash, carry, instruction, membership_hash, funding_hash, state, finalized_slot, week_frame, close_receipt, expiry_slot, expiry_frame, expiry_receipt) FROM stdin;
\.


--
-- Data for Name: issuer_btc_conversion_output_uses; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_btc_conversion_output_uses (intent_id, bucket, operation_id, receipt_hash, released, expiry_receipt) FROM stdin;
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
-- Data for Name: issuer_keys; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_keys (key_id, epoch, purpose, spki, sealed_private_key, admitted_evidence, quote_public_key, sealed_quote_key) FROM stdin;
\\x3a239fa4458b39a71a30bd7c7bd67a521b9f48f7273bb6509572190b1decdea9	1	1	\\x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111	\\x2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222	\N	\N	\N
\.


--
-- Data for Name: issuer_quotes; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_quotes (quote_id, quote, key_id, batch_hash, deposit_owner, sealed_deposit_key, price_observed_at, payment_signature, payment_payer, payment_slot, payment_time, payment_amount, issued_response, signed_quote, policy_version, policy_hash) FROM stdin;
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
-- Data for Name: issuer_transparency_cursor; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_transparency_cursor (singleton, checkpoint) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batches; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batches (batch_id, config_hash, member_hash, member_count, state, nonce_address, nonce_value, message, packet, transaction_signature, finalized_slot, execution_error, fee, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_movements; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_movements (movement_id, payment_signature, kind, config_hash, source, destination, destination_owner, amount, ready_at, state, nonce_address, nonce_value, message, packet, transaction_signature, finalized_slot, execution_error, fee, batch_id, rent) FROM stdin;
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
-- Data for Name: issuer_treasury_batch_members; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batch_members (movement_id, batch_id, ordinal) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_batch_costs; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_batch_costs (transaction_signature, movement_id, fee, rent) FROM stdin;
\.


--
-- Data for Name: issuer_treasury_weekly; Type: TABLE DATA; Schema: public; Owner: andreyyurlov
--

COPY public.issuer_treasury_weekly (batch_id, week, asset, cutoff, mint, config_hash, amount, witness, operations, carry_before, carry_after, membership_hash, policy_version, policy_hash, burn, burn_carry_before, burn_carry_after, operations_carry_before, operations_carry_after, reserve_before, reserve_after) FROM stdin;
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
-- PostgreSQL database dump complete
--

\unrestrict cN5PGhsoufv9KzbYL7Ei1cUryfym7bSY9eWlzttTZkHeUFpVCVuitYFMMLjlA3B

