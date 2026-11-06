/* Static artifact presentation only. Mesh owns account authentication and money arithmetic. */
(() => {
  const families = ['burns', 'witnesses', 'proofs'];
  const fail = () => { throw new Error('Invalid bounded history'); };
  const integer = value => { if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 18446744073709551615n) fail(); };
  const hash = value => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail(); };
  const address = value => { if (typeof value !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) fail(); };
  const bounded = (value, low, high) => { if (!Number.isInteger(value) || value < low || value > high) fail(); };
  const same = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  function legacyValues(value, kind) {
    if (!value || !['available','unavailable','disagreed'].includes(value.availability)) fail();
    if (value.availability !== 'available') { if (value.rows !== undefined || value.receipts !== undefined) fail(); return; }
    if (value.schema_version !== 1 || value.context_kind !== 'legacy-v1' || value.asset_scope !== 'configured-legacy-mint' || value.decimals !== 6 || value.selection_scope !== 'explicit-indexed-records-only' || value.bank_scope !== 'this-value-page-only' || typeof value.code_current !== 'boolean') fail();
    if (['token','rewards','usdc_mint','morse_mint','assets','valuation'].some(key => value[key] !== undefined)) fail();
    for (const key of ['context_slot','source_time_unix']) integer(value[key]);
    for (const key of ['snapshot_digest','log_id','service_public_key']) hash(value[key]);
    address(value.judge); address(value.mint);
    if (typeof value.log_name !== 'string' || !/^[a-z0-9-]{1,32}$/.test(value.log_name)) fail();
    if (kind === 'witnesses') {
      if (!Array.isArray(value.rows) || value.rows.length < 1 || value.rows.length > 17 || new Set(value.rows.map(row => row.address)).size !== value.rows.length) fail();
      for (const [index,row] of value.rows.entries()) {
        if (row.kind !== (index === 0 ? 'directory' : 'witness') || row.asset !== undefined || row.mint !== undefined || row.pending_units !== null) fail();
        if (index === 0 ? row.witness_id !== '' || row.public_key !== null : !/^[a-z0-9-]{1,64}$/.test(row.witness_id)) fail();
        address(row.address); if(index > 0) hash(row.public_key);
        if(index === 0 && row.status === 'unbonded') { if(['principal_units','vault_balance_units','donation_surplus_units'].some(key => row[key] !== null)) fail(); continue; }
        if(!['active','unbonding','slashed','withdrawn'].includes(row.status) || row.liability_scope !== 'principal-only-v1-no-v2-pending-interpretation') fail();
        address(row.owner); address(row.vault);
        for(const key of ['principal_units','vault_balance_units','donation_surplus_units','bonded_at_unix','unbond_at_unix','slashed_at_unix']) integer(row[key]);
      }
    } else {
      if(value.proof_scope !== 'onchain-recorded-receipts-not-independent-fork-reverification' || !Array.isArray(value.receipts) || value.receipts.length > 16 || new Set(value.receipts.map(row => row.address)).size !== value.receipts.length) fail();
      for(const row of value.receipts) {
        if(row.version !== 1 || row.status !== 'settled' || ![1,2,3].includes(row.kind) || typeof row.anchored !== 'boolean' || row.assets !== undefined || row.row_identity_scope !== 'recorded-legacy-address-and-key-no-id-seed' || !Array.isArray(row.rows) || row.rows.length > 16) fail();
        for(const key of ['address','finder','submitter']) address(row[key]); hash(row.proof_hash);
        for(const key of ['slashed_at_unix','total_slashed_units','finder_units','directory_slashed_units','verified_signature_mask','verified_signatures']) integer(row[key]);
        if(BigInt(row.verified_signature_mask).toString(2).replaceAll('0','').length !== Number(row.verified_signatures)) fail();
        for(const witness of row.rows) { address(witness.witness);hash(witness.public_key);for(const key of ['principal_units','slashed_units','finder_units']) integer(witness[key]); }
      }
    }
  }
  function validate(report, validators) {
    const history = report.history;
    const legacy = history?.context_kind === 'legacy-v1';
    if (history?.context_kind !== undefined && !legacy) fail();
    if (legacy && (report.burns.length !== 0 || report.bonds.availability !== 'unavailable' || report.slashes.availability !== 'unavailable')) fail();
    const eligible = row => (row.verification === 'supported' || (legacy && row.verification === 'legacy')) && row.value_status === 'requested';
    if (!history || history.schema_version !== 1 || history.scope !== 'bounded-filtered-family-discovery' || history.global_totals !== null || history.provider_independence !== 'not-established' || history.bank_scope !== 'per-discovery-section-and-value-page' || report.scope === 'bootstrap') fail();
    for (const kind of families) {
      const section = history[kind];
      if (!section || !['available', 'unavailable', 'disagreed', 'not-configured'].includes(section.availability)) fail();
      bounded(section.upper_bound, 1, 128);
      if (legacy && kind === 'burns' && (section.availability !== 'not-configured' || section.reason !== 'legacy-context-has-no-token-program')) fail();
      if (section.availability !== 'available') {
        if (section.records !== undefined || section.pages !== undefined || section.record_count !== undefined) fail();
        continue;
      }
      if (section.discovery_scope !== 'complete-returned-filtered-family-at-index-bank' || section.value_bank_scope !== 'separate-from-discovery-and-other-pages' || section.legacy_rendering !== (legacy ? 'versioned-single-mint-v1-values' : 'proof-v1-identifiers-only') || typeof section.code_current !== 'boolean' || typeof section.supported_layouts_complete !== 'boolean') fail();
      integer(section.index_slot); integer(section.source_time_unix); hash(section.snapshot_digest); hash(section.binding); address(section.program);
      if(legacy) {if(section.context_kind !== 'legacy-v1' || section.asset_scope !== 'configured-legacy-mint') fail(); address(section.mint);}
      if (!Array.isArray(section.release_pins) || ![1, 3].includes(section.release_pins.length) || new Set(section.release_pins.map(pin => pin.program)).size !== section.release_pins.length) fail();
      for (const pin of section.release_pins) { address(pin.program); integer(pin.deployment_slot); }
      if (!section.release_pins.some(pin => pin.program === section.program) || (legacy ? section.release_pins.length !== 1 : kind !== 'burns' && section.release_pins.length !== 3)) fail();
      if (!Array.isArray(section.records) || !Array.isArray(section.pages)) fail();
      bounded(section.record_count, 0, section.upper_bound);
      if (section.records.length !== section.record_count || new Set(section.records.map(row => row.address)).size !== section.records.length) fail();
      for (const row of section.records) {
        address(row.address); bounded(row.version, 0, 255);
        if (!['supported', 'legacy', 'unsupported-layout', 'unsupported-family'].includes(row.verification) || typeof row.canonical_identity !== 'boolean') fail();
        const known = ['supported', 'legacy'].includes(row.verification);
        if (row.canonical_identity !== known) fail();
        if (!known) {
          if (row.value_status !== 'unsupported' || row.epoch !== null || row.witness_id !== '' || row.public_key !== null || row.proof_hash !== null || row.registry_status !== -1) fail();
        } else if (kind === 'burns') {
          if (row.verification !== 'supported' || ![1, 2].includes(row.version) || row.value_status !== 'requested' || row.witness_id !== '' || row.public_key !== null || row.proof_hash !== null || row.registry_status !== -1) fail();
          integer(row.epoch);
        } else if (kind === 'witnesses') {
          if (row.verification !== 'supported' || row.version !== 1 || row.epoch !== null || row.proof_hash !== null || !/^[a-z0-9-]{1,64}$/.test(row.witness_id)) fail();
          bounded(row.registry_status, 0, 4); hash(row.public_key);
          if (row.value_status !== (row.registry_status === 0 ? 'registry-only' : 'requested')) fail();
        } else {
          if (row.epoch !== null || row.witness_id !== '' || row.public_key !== null || row.registry_status !== -1) fail();
          hash(row.proof_hash);
          if ((legacy && row.version !== 1) || (row.version === 1 ? row.verification !== 'legacy' || row.value_status !== (legacy ? 'requested' : 'legacy-unrendered') : row.version !== 2 || row.verification !== 'supported' || row.value_status !== 'requested')) fail();
        }
      }
      const allKnown = section.records.every(row => row.canonical_identity);
      if (section.supported_layouts_complete !== allKnown) fail();
      const requested = section.records.filter(eligible), seen = [];
      let valuesComplete = true;
      for (const [index, page] of section.pages.entries()) {
        if (!page || page.page !== index || typeof page.complete !== 'boolean' || !Array.isArray(page.requested_addresses)) fail();
        bounded(page.requested_addresses.length, 1, 16);
        const rows = requested.slice(seen.length, seen.length + page.requested_addresses.length);
        if (!same(page.requested_addresses, rows.map(row => row.address))) fail();
        seen.push(...page.requested_addresses);
        let complete;
        if (kind === 'burns') {
          if (page.bank_scope !== 'per-burn-record' || !Array.isArray(page.values) || page.values.length !== rows.length) fail();
          for (const [at, value] of page.values.entries()) {
            validators.burn(value);
            if (value.epoch !== rows[at].epoch) fail();
            if (value.availability === 'available' && (value.week_address !== rows[at].address || value.program !== section.program)) fail();
          }
          complete = page.values.every(value => value.availability === 'available');
        } else {
          if (page.bank_scope !== 'this-value-page-only') fail();
          if(legacy) legacyValues(page.values, kind); else validators.collateral(page.values, kind === 'witnesses' ? 'bonds' : 'slashes');
          complete = page.values.availability === 'available';
          if (complete) {
            if (page.values.judge !== section.program || page.values.log_id !== section.binding || (legacy ? page.values.mint !== section.mint : !same([...section.release_pins.map(pin => pin.program)].sort(), [page.values.judge, page.values.token, page.values.rewards].sort()))) fail();
            const values = kind === 'witnesses' ? page.values.rows.slice(1) : page.values.receipts;
            if (values.length !== rows.length) fail();
            for (const [at, value] of values.entries()) {
              if (kind === 'witnesses' ? value.witness_id !== rows[at].witness_id || value.public_key !== rows[at].public_key : value.address !== rows[at].address || value.proof_hash !== rows[at].proof_hash) fail();
            }
          }
        }
        if (page.complete !== complete) fail();
        valuesComplete &&= complete;
        for (const value of kind === 'burns' ? page.values : [page.values]) {
          if (value.availability === 'available' && BigInt(value.context_slot) < BigInt(section.index_slot)) fail();
        }
      }
      if (!same(seen, requested.map(row => row.address))) fail();
      const complete = allKnown && (legacy || section.records.every(row => row.verification !== 'legacy')) && valuesComplete;
      if (section.value_completeness !== (complete ? 'complete-for-applicable-supported-records' : 'incomplete')) fail();
    }
    return history;
  }
  function observations(history) {
    if (!history) return [];
    return families.flatMap(kind => {
      const section = history[kind];
      if (section.availability === 'not-configured') return [];
      if (section.availability !== 'available') return [section];
      return [section, ...section.pages.flatMap(page => kind === 'burns' ? page.values : [page.values])];
    });
  }
  function incomplete(history) { return !!history && families.some(kind => history[kind].availability === 'available' && history[kind].value_completeness === 'incomplete'); }
  function mount(document, report, helpers, now) {
    const target = document.getElementById('history-records'); if (!target) return;
    target.replaceChildren();
    const node = (tag, text, className) => { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; };
    if (!report?.history) { target.append(node('p', 'No discovery index is published. Selected records below do not establish complete history.', 'empty')); return; }
    target.append(node('p', 'Configured sources agreed on the whole returned filtered set at each index bank. This is not proof that providers omitted no matching account. Value pages use separate banks; no global total is calculated.', 'source'));
    const tabs = node('nav', '', 'history-tabs'); tabs.setAttribute('aria-label', 'History families');
    const content = node('div', '', 'history-content'); target.append(tabs, content);
    let selected = 'burns', offset = 0;
    const sourceState = value => `${value.availability}${value.availability === 'available' && helpers.isStale(report, value, now) ? ' · stale' : ''}${value.availability === 'available' && !value.code_current ? ' · code pin changed' : ''}`;
    const buttons = new Map();
    for (const kind of families) {
      const button = node('button', kind === 'burns' ? 'Burn weeks' : kind === 'witnesses' ? 'Witness identities' : 'Proof receipts');
      button.type = 'button'; button.dataset.family = kind;
      button.addEventListener('click', () => { selected = kind; offset = 0; draw(); }); tabs.append(button); buttons.set(kind, button);
    }
    function draw() {
      for (const [kind, button] of buttons) button.setAttribute('aria-pressed', String(kind === selected));
      content.replaceChildren(); const section = report.history[selected];
      content.append(node('h3', `${selected === 'burns' ? 'Burn weeks' : selected === 'witnesses' ? 'Witness identities' : 'Proof receipts'} · ${sourceState(section)}`));
      if (section.availability !== 'available') { content.append(node('p', section.availability === 'not-configured' ? 'This context has no configured token program. Burn history was not queried.' : 'No agreeing authenticated discovery bank is available. An unavailable index is not an empty history.', 'empty')); return; }
      const legacy = report.history.context_kind === 'legacy-v1';
      if(legacy) content.append(node('p', `Legacy v1 · configured mint ${section.mint} · 6 decimals. No USDC, MORSE or fiat identity is assigned.`, 'source'));
      content.append(node('p', `${section.record_count} returned records · upper bound ${section.upper_bound} · index slot ${section.index_slot} · ${helpers.time(section.source_time_unix)} · ${section.value_completeness}`, 'source'));
      if (!section.records.length) content.append(node('p', 'The agreed filtered set was empty at this index bank. This does not describe every program, version or future bank.', 'empty'));
      const warnings = section.pages.flatMap(page => (selected === 'burns' ? page.values : [page.values]).map(value => ({ page: page.page, value })))
        .filter(({ value }) => value.availability !== 'available' || !value.code_current || helpers.isStale(report, value, now));
      for (const { page, value } of warnings) content.append(node('p', `Separate value page ${page + 1}: ${sourceState(value)}. Its bank does not apply to other pages.`, 'source'));
      const releases = node('details', '', 'metadata'); releases.append(node('summary', 'Expected program release pins'));
      for (const pin of section.release_pins) releases.append(node('p', `${pin.program} · deployment slot ${pin.deployment_slot}`)); content.append(releases);
      const selectedRows = section.records.slice(offset, offset + 8);
      for (const record of selectedRows) {
        const card = node('article', '', 'week history-record'); card.dataset.address = record.address;
        const title = selected === 'burns' && record.epoch ? `Week ${record.epoch}` : record.witness_id || record.address;
        card.append(node('h4', title), node('p', `Layout ${record.version} · ${record.verification} · ${record.value_status}`));
        const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Indexed identity'), node('p', record.address));
        if (record.proof_hash) metadata.append(node('p', `Proof: ${record.proof_hash}`));
        if (record.public_key) metadata.append(node('p', `Witness key: ${record.public_key}`));
        metadata.append(node('p', `Program: ${section.program}`), node('p', `Binding: ${section.binding}`), node('p', `Index digest: ${section.snapshot_digest}`)); card.append(metadata);
        const page = section.pages.find(page => page.requested_addresses.includes(record.address));
        if (!page) card.append(node('p', record.value_status === 'registry-only' ? 'Registered identity only. No bond balance, zero balance, eligibility or operator independence is inferred.' : record.value_status === 'legacy-unrendered' ? 'Canonical legacy proof identifier retained. Legacy custody amounts are not rendered by this v2 reader.' : 'Unvalidated layout observation. Canonical identity and custody values are unavailable.', 'source'));
        else {
          const index = page.requested_addresses.indexOf(record.address), value = selected === 'burns' ? page.values[index] : page.values;
          card.append(node('p', `Value page ${page.page + 1} · ${sourceState(value)}`, 'state'));
          if (value.availability !== 'available') card.append(node('p', 'Values unavailable for this identifier; it remains explicitly indexed.'));
          else {
            card.append(node('p', `Value context slot ${value.context_slot} · ${helpers.time(value.source_time_unix)} · this bank only`, 'source'));
            const dl = node('dl', '');
            const add = (label, amount) => { const pair = node('div', ''); pair.append(node('dt', label), node('dd', amount === null ? 'Unavailable until settlement' : helpers.formatUnits(amount))); dl.append(pair); };
            if (selected === 'burns') { add('Budget · USDC', value.budget_units); add('Spent · USDC', value.spent_units); add('Burned · MORSE', value.burned_units); if (value.receipt) add('Carried · USDC', value.receipt.carried_units); }
            else if (legacy && selected === 'witnesses') { const row = value.rows[index + 1]; add('Principal · configured legacy mint', row.principal_units); add('Donation surplus · configured legacy mint', row.donation_surplus_units); card.append(node('p', 'V1 records have no v2 pending-liability field. The directory row is repeated per page and is not summed.', 'source')); }
            else if(legacy) {const receipt = value.receipts[index]; add('Slashed · configured legacy mint', receipt.total_slashed_units); add('Finder · configured legacy mint', receipt.finder_units); card.append(node('p', 'Receipt witness rows retain their recorded address and public key; the v1 layout has no witness ID seed for independent canonical identity validation.', 'source'));}
            else if (selected === 'witnesses') { const row = value.rows[index + 1]; add(`Principal · ${row.asset}`, row.principal_units); add(`Pending liability · ${row.asset}`, row.pending_liability_units); add(`Donation surplus · ${row.asset}`, row.donation_surplus_units); card.append(node('p', 'The directory row is repeated in each source page and is not added across pages.', 'source')); }
            else for (const asset of value.receipts[index].assets) { add(`Slashed · ${asset.asset}`, asset.slashed_units); add(`Finder · ${asset.asset}`, asset.finder_units); }
            card.append(dl);
          }
        }
        content.append(card);
      }
      if (section.records.length) {
        const controls = node('nav', '', 'history-pages'); controls.setAttribute('aria-label', 'Indexed record pages');
        const previous = node('button', 'Previous'), next = node('button', 'Next'); previous.type = next.type = 'button'; previous.disabled = offset === 0; next.disabled = offset + 8 >= section.records.length;
        previous.addEventListener('click', () => { offset -= 8; draw(); }); next.addEventListener('click', () => { offset += 8; draw(); });
        controls.append(previous, node('span', `${offset + 1}–${Math.min(offset + 8, section.records.length)} of ${section.records.length}`), next); content.append(controls);
      }
    }
    draw();
  }
  globalThis.MorseNetworkHistory = { validate, observations, incomplete, mount };
})();
