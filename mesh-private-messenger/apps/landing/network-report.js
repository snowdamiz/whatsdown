/* Browser presentation only. Mesh authenticates and computes every published unit. */
(() => {
  const states = ['scheduled', 'delayed', 'missed', 'executed', 'closed', 'unfunded'];
  function integer(value) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || (value.length === 20 && value > '18446744073709551615')) throw new Error('Invalid report integer');
    return value;
  }
  function formatUnits(value) {
    const digits = integer(value).padStart(7, '0');
    return `${digits.slice(0, -6).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}.${digits.slice(-6)}`;
  }
  function hash(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error('Invalid record digest'); }
  function address(value) { if (typeof value !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) throw new Error('Invalid account address'); }
  function receiptAmount(value, settled) {
    if (settled) integer(value); else if (value !== null) throw new Error('Prepared amount must be unavailable');
  }
  function collateral(section, kind) {
    if (!section || !['available', 'unavailable', 'disagreed'].includes(section.availability)) throw new Error('Invalid collateral availability');
    if (section.availability !== 'available') {
      if (section.rows !== undefined || section.receipts !== undefined) throw new Error('Unavailable collateral contains amounts');
      return;
    }
    if (section.schema_version !== 2 || section.selection_scope !== 'explicit-indexed-records-only' || section.bank_scope !== 'this-section-only' || section.decimals !== 6 || typeof section.code_current !== 'boolean') throw new Error('Unsupported collateral schema');
    integer(section.context_slot); integer(section.source_time_unix); hash(section.snapshot_digest); hash(section.log_id); hash(section.service_public_key);
    for (const key of ['judge', 'token', 'rewards', 'usdc_mint', 'morse_mint']) address(section[key]);
    if (typeof section.log_name !== 'string' || !/^[a-z0-9-]{1,32}$/.test(section.log_name) || section.usdc_mint === section.morse_mint) throw new Error('Invalid collateral identity');
    if (kind === 'bonds') {
      if (!section.valuation || section.valuation.availability !== 'unavailable' || !Array.isArray(section.rows) || section.rows.length < 1 || section.rows.length > 17 || new Set(section.rows.map(row => row.address)).size !== section.rows.length) throw new Error('Invalid selected bonds');
      for (const [index, row] of section.rows.entries()) {
        if (row.kind !== (index === 0 ? 'directory' : 'witness') || !['active', 'unbonding', 'slashed', 'withdrawn'].includes(row.status) || !['USDC', 'MORSE'].includes(row.asset)) throw new Error('Invalid bond status');
        if (typeof row.witness_id !== 'string' || (index === 0 ? row.witness_id !== '' : !/^[a-z0-9-]{1,64}$/.test(row.witness_id))) throw new Error('Invalid selected witness');
        hash(row.public_key); for (const key of ['address', 'owner', 'mint', 'vault']) address(row[key]);
        if (row.mint !== section[row.asset === 'USDC' ? 'usdc_mint' : 'morse_mint']) throw new Error('Mismatched collateral asset');
        for (const key of ['principal_units', 'pending_recorded_units', 'pending_liability_units', 'vault_balance_units', 'donation_surplus_units', 'bonded_at_unix', 'unbond_at_unix', 'slashed_at_unix', 'underwater_since_unix', 'pending_target_usd_micros']) integer(row[key]);
        const other = row.opposite_asset_vault;
        if (!other || !['present', 'absent'].includes(other.availability) || (other.availability === 'absent' && other.balance_units !== null)) throw new Error('Invalid opposite asset observation');
        if (other.availability === 'present') integer(other.balance_units);
      }
    } else {
      if (section.proof_scope !== 'onchain-recorded-receipts-not-independent-fork-reverification' || !Array.isArray(section.receipts) || section.receipts.length > 16 || new Set(section.receipts.map(row => row.proof_hash)).size !== section.receipts.length) throw new Error('Invalid selected receipts');
      for (const receipt of section.receipts) {
        if (!['prepared', 'settled'].includes(receipt.status) || ![1, 2, 3].includes(receipt.kind) || typeof receipt.anchored !== 'boolean' || !Array.isArray(receipt.rows) || receipt.rows.length > 16 || !Array.isArray(receipt.assets) || receipt.assets.length !== 2) throw new Error('Invalid slash receipt');
        hash(receipt.proof_hash); for (const key of ['address', 'finder', 'submitter', 'stage']) address(receipt[key]);
        for (const key of ['prepared_at_unix', 'settled_at_unix', 'deadline_ms', 'verified_signature_mask', 'verified_signatures']) integer(receipt[key]);
        if (BigInt(receipt.verified_signatures) > 64n) throw new Error('Invalid signature count');
        for (const [index, asset] of receipt.assets.entries()) {
          if (asset.asset !== ['USDC', 'MORSE'][index]) throw new Error('Mismatched slash assets');
          for (const key of ['slashed_units', 'finder_units', 'directory_slashed_units']) receiptAmount(asset[key], receipt.status === 'settled');
        }
        for (const row of receipt.rows) {
          if (!['USDC', 'MORSE'].includes(row.asset)) throw new Error('Invalid slash asset');
          hash(row.identity); hash(row.public_key); address(row.witness); integer(row.bonded_at_unix);
          for (const key of ['principal_units', 'slashed_units', 'finder_units']) receiptAmount(row[key], receipt.status === 'settled');
        }
      }
    }
  }
  function validateReport(report) {
    if (!report || report.schema_version !== 1 || !['bootstrap', 'local-fixture', 'configured-rpc'].includes(report.scope) || report.phase5_complete !== false || report.provider_independence !== 'not-established' || !['selected-epochs-only', 'bounded-filtered-index-with-separate-value-pages'].includes(report.history_completeness)) throw new Error('Unsupported report');
    if (!Array.isArray(report.burns) || report.burns.length > 16 || new Set(report.burns.map(row => row.epoch)).size !== report.burns.length) throw new Error('Invalid selected weeks');
    if (report.scope !== 'bootstrap') {
      integer(report.generated_at_unix); integer(report.max_age_seconds);
      if (BigInt(report.max_age_seconds) < 1n || BigInt(report.max_age_seconds) > 86400n) throw new Error('Invalid freshness policy');
    } else if (report.burns.length) throw new Error('Bootstrap cannot contain executions');
    for (const row of report.burns) {
      integer(row.epoch);
      if (!['available', 'unavailable', 'disagreed'].includes(row.availability)) throw new Error('Invalid availability');
      if (row.availability !== 'available') continue;
      if (!states.includes(row.status) || typeof row.code_current !== 'boolean' || row.decimals !== 6 || !Array.isArray(row.rows) || ![0, 24].includes(row.rows.length)) throw new Error('Invalid burn record');
      for (const key of ['context_slot', 'source_time_unix', 'remaining_units', 'week_donation_surplus_units', 'carry_donation_surplus_units']) integer(row[key]);
      for (const key of ['budget_units', 'spent_units', 'burned_units']) if (row[key] !== null) integer(row[key]);
      if (row.status !== 'unfunded' && [row.budget_units, row.spent_units, row.burned_units].includes(null)) throw new Error('Missing burn units');
      if (!row.quote || row.quote.status !== 'unavailable' || row.quote.source_time_unix !== null) throw new Error('Unsupported quote source');
      if (row.status === 'closed' && !row.receipt) throw new Error('Closed week needs receipt');
      if (row.receipt) for (const key of ['budget_units', 'spent_units', 'burned_units', 'carried_units', 'closed_at_unix']) integer(row.receipt[key]);
      for (const [index, chunk] of row.rows.entries()) {
        if (chunk.index !== index || !['scheduled', 'delayed', 'missed', 'executed', 'carried'].includes(chunk.status)) throw new Error('Invalid burn chunk');
        for (const key of ['input_usdc_units', 'burned_morse_units', 'execute_at_unix', 'window_end_unix']) integer(chunk[key]);
      }
    }
    collateral(report.bonds, 'bonds'); collateral(report.slashes, 'slashes');
    if (report.scope === 'bootstrap' && [report.bonds, report.slashes].some(section => section.availability !== 'unavailable')) throw new Error('Bootstrap cannot contain collateral records');
    if (report.history_completeness === 'bounded-filtered-index-with-separate-value-pages') {
      if (!globalThis.MorseNetworkHistory) throw new Error('History viewer unavailable');
      globalThis.MorseNetworkHistory.validate(report, {
        collateral,
        burn: value => validateReport({ ...report, history: undefined, history_completeness: 'selected-epochs-only', burns: [value], bonds: { availability: 'unavailable' }, slashes: { availability: 'unavailable' } })
      });
    } else if (report.history !== undefined) throw new Error('Unexpected discovery history');
    return report;
  }
  function isStale(report, row, now) {
    const age = BigInt(report.max_age_seconds), current = BigInt(now);
    return [report.generated_at_unix, row.source_time_unix].some(value => current - BigInt(value) > age || BigInt(value) - current > 60n);
  }
  function reportState(report, now = Math.floor(Date.now() / 1000)) {
    validateReport(report);
    if (report.scope === 'bootstrap') return 'bootstrap';
    if (report.scope === 'local-fixture') return 'local-fixture';
    const sections = [...report.burns, report.bonds, report.slashes, ...(globalThis.MorseNetworkHistory?.observations(report.history) || [])];
    if (sections.some(row => row.availability === 'disagreed')) return 'disagreed';
    const available = sections.filter(row => row.availability === 'available');
    if (!available.length) return 'unavailable';
    if (available.some(row => !row.code_current)) return 'code-changed';
    if (available.some(row => isStale(report, row, now))) return 'stale';
    if (globalThis.MorseNetworkHistory?.incomplete(report.history)) return 'incomplete';
    return 'available';
  }
  const publicationStates = ['bootstrap', 'collecting', 'available', 'stale', 'unavailable', 'disagreed', 'code-changed', 'incomplete', 'identity-mismatch', 'future-clock', 'clock-rollback', 'storage-unavailable', 'capacity-refused', 'receipt-conflict'];
  function validatePublication(value) {
    if (!value || value.schema_version !== 1 || value.policy !== 'morse-public-snapshot-v1' || value.phase5_complete !== false || value.provider_independence !== 'not-established'
      || !publicationStates.includes(value.status) || !Number.isSafeInteger(value.generation) || value.generation < 0
      || !Array.isArray(value.observations) || value.observations.length > 32 || !Array.isArray(value.settled_history) || value.settled_history.length > 128
      || !Number.isInteger(value.refused_new_settled_observations) || value.refused_new_settled_observations < 0) throw new Error('Invalid publication');
    integer(value.generated_at_unix); if (value.last_attempt_at_unix !== null) integer(value.last_attempt_at_unix);
    hash(value.policy_sha256); hash(value.generator_sha256);
    if (value.last_good !== null) { validateReport(value.last_good.report); hash(value.last_good.report_sha256); integer(value.last_good.completed_at_unix); }
    if (value.status === 'available') {
      if (!value.current || !value.last_good || JSON.stringify(value.current) !== JSON.stringify(value.last_good.report)) throw new Error('Current association missing');
      validateReport(value.current);
    } else if (value.current !== null) throw new Error('Failed publication contains current data');
    const seen = new Set();
    for (const row of value.settled_history) {
      if (![1, 2].includes(row.schema_version) || typeof row.identity !== 'string' || row.identity.length > 256 || seen.has(row.identity) || row.receipt?.status !== 'settled') throw new Error('Invalid retained receipt');
      seen.add(row.identity); address(row.judge); hash(row.log_id); hash(row.receipt.proof_hash);
      for (const key of ['source_time_unix', 'context_slot', 'first_observed_at_unix', 'last_observed_at_unix']) integer(row[key]);
    }
    return value;
  }
  function mountPublication(document, value, now) {
    try { validatePublication(value); } catch { mount(document, null, now); return; }
    const report = value.current || value.last_good?.report;
    mount(document, report || { schema_version: 1, scope: 'bootstrap', phase5_complete: false, provider_independence: 'not-established', history_completeness: 'selected-epochs-only', burns: [], bonds: { availability: 'unavailable' }, slashes: { availability: 'unavailable' } }, now);
    const status = document.getElementById('report-status'), detail = document.getElementById('report-detail');
    const node = (tag, text, className) => { const element = document.createElement(tag); element.textContent = text; if (className) element.className = className; return element; };
    if (value.status !== 'available') {
      const labels = { bootstrap: 'Awaiting published snapshot', collecting: 'Refreshing current snapshot', unavailable: 'Current snapshot unavailable', stale: 'Current snapshot is stale', disagreed: 'Sources disagree', 'code-changed': 'Code pin changed', incomplete: 'Current history is incomplete', 'identity-mismatch': 'Report policy or build changed', 'future-clock': 'Source clock is ahead', 'clock-rollback': 'Publication clock moved backwards', 'storage-unavailable': 'Stored report unavailable', 'capacity-refused': 'Current snapshot unavailable · history capacity reached', 'receipt-conflict': 'Current snapshot unavailable · receipt conflict' };
      status.textContent = labels[value.status]; status.dataset.state = value.status;
      detail.textContent = `Latest attempt: ${time(value.last_attempt_at_unix)}. ${report?.scope === 'local-fixture' ? 'Local fixture observations. ' : ''}${report ? 'All report values below are historical last-good observations; they are not current balances.' : 'No accepted report is available.'} Provider independence has not been established.`;
      for (const id of ['history-records', 'burn-records', 'bond-records', 'slash-records']) {
        const target = document.getElementById(id); if (target && report) target.prepend(node('p', 'Historical last-good data · current data unavailable', 'source'));
      }
      for (const badge of document.querySelectorAll('.state')) badge.textContent += ' · historical';
    }
    const target = document.getElementById('slash-records');
    target.append(node('h3', 'Retained settled observations'));
    target.append(node('p', 'Previously observed onchain settlements remain visible across outages and bounded index changes. These are historical receipts, not current balances or independent fork verification. Absence does not establish that no slash occurred.', 'source'));
    if (!value.settled_history.length) target.append(node('p', 'No settled observations retained yet. This is not evidence of no slash.', 'empty'));
    for (const row of value.settled_history) {
      const card = node('article', '', 'week retained-slash-record');
      card.append(node('h4', `Recorded settled slash · ${row.receipt.proof_hash.slice(0, 12)}…`));
      const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Retained receipt identity'), node('p', `Proof ${row.receipt.proof_hash} · Judge ${row.judge} · Log ${row.log_id}`)); card.append(metadata);
      card.append(node('p', `Source time ${time(row.source_time_unix)} · Finalized context slot ${row.context_slot} · Last observed ${time(row.last_observed_at_unix)}`, 'source'));
      target.append(card);
    }
  }
  function time(value) {
    if (value == null) return 'Unavailable';
    const date = new Date(Number(value) * 1000);
    return Number.isNaN(date.getTime()) ? `${value} Unix seconds` : date.toISOString().replace('.000Z', ' UTC').replace('T', ' ');
  }
  const messages = {
    bootstrap: ['Awaiting published records', 'No live report is configured. Burns, bonds and slashes are unavailable; this does not establish that no activity occurred.'],
    'local-fixture': ['Local fixture preview', 'These records come from a disposable local SBF bank. They are test executions and do not count toward published live weekly burns.'],
    available: ['Configured snapshot available', 'Two or more configured sources agreed on these selected finalized records. Provider independence has not been established.'],
    stale: ['Snapshot is stale', 'The retrieval time or chain source time exceeds this report’s configured age limit. Historical values remain visible below.'],
    'code-changed': ['Code pin changed', 'The current program code differs from the configured release slot. Decoded account values remain visible; this report does not qualify the changed code.'],
    disagreed: ['Sources disagree', 'Valid finalized snapshots differ. Affected sections have no published balances or amounts.'],
    incomplete: ['History values are incomplete', 'The bounded index retains every returned identifier, but some layouts or value pages are unavailable. No complete historical total is inferred.'],
    unavailable: ['Snapshot unavailable', 'Fewer than two valid finalized snapshots agree. Unavailable records do not establish that no activity occurred.']
  };
  function mount(document, raw, now = Math.floor(Date.now() / 1000)) {
    if (raw?.policy === 'morse-public-snapshot-v1') return mountPublication(document, raw, now);
    const status = document.getElementById('report-status');
    const detail = document.getElementById('report-detail');
    const body = document.getElementById('burn-records');
    const node = (tag, text, className) => { const element = document.createElement(tag); element.textContent = text; if (className) element.className = className; return element; };
    const bonds = document.getElementById('bond-records'), slashes = document.getElementById('slash-records');
    body.replaceChildren(); bonds.replaceChildren(); slashes.replaceChildren();
    globalThis.MorseNetworkHistory?.mount(document, null, { isStale, time, formatUnits }, now);
    let report;
    try { report = validateReport(raw); } catch {
      status.textContent = 'Report unavailable'; detail.textContent = 'This report could not be read. No amounts are shown.'; body.append(node('p', 'No readable weekly records.')); bonds.append(node('p', 'Bond amounts unavailable.')); slashes.append(node('p', 'Slash amounts unavailable.')); return;
    }
    globalThis.MorseNetworkHistory?.mount(document, report, { isStale, time, formatUnits }, now);
    const state = reportState(report, now);
    [status.textContent, detail.textContent] = messages[state]; status.dataset.state = state;
    document.getElementById('retrieved-at').textContent = time(report.generated_at_unix);
    document.getElementById('source-scope').textContent = report.scope === 'bootstrap' ? 'Awaiting source policy' : report.scope === 'local-fixture' ? 'Disposable local bank' : 'Operator supplied configuration';
    document.getElementById('age-limit').textContent = report.max_age_seconds ? `${report.max_age_seconds} seconds` : 'Unconfigured';
    if (!report.burns.length) body.append(node('p', 'No weekly records have been published in this report.', 'empty'));
    renderCollateral(report, bonds, slashes, node, now);
    for (const week of report.burns) {
      const article = node('article', '', 'week');
      const heading = node('header', ''); heading.append(node('h3', `Week ${week.epoch}`));
      const available = week.availability === 'available';
      const stale = available && report.scope === 'configured-rpc' && isStale(report, week, now);
      heading.append(node('span', available ? `${week.status}${stale ? ' · stale' : ''}${!week.code_current ? ' · code pin changed' : ''}` : week.availability, 'state'));
      article.append(heading);
      if (!available) { article.append(node('p', 'No agreeing finalized record. Amounts unavailable.')); body.append(article); continue; }
      const dl = node('dl', '');
      const add = (label, value) => { const group = node('div', ''); group.append(node('dt', label), node('dd', value)); dl.append(group); };
      const amount = value => value == null ? 'Unavailable' : formatUnits(value);
      add('Budget · USDC', amount(week.budget_units)); add('Spent · USDC', amount(week.spent_units)); add('Burned · MORSE', amount(week.burned_units));
      add('Carried · USDC', week.receipt ? amount(week.receipt.carried_units) : 'No close receipt');
      add('Week donation surplus · USDC', amount(week.week_donation_surplus_units)); add('Carry donation surplus · USDC', amount(week.carry_donation_surplus_units));
      article.append(dl);
      article.append(node('p', `Finalized context slot ${week.context_slot} · Source time ${time(week.source_time_unix)}`, 'source'));
      article.append(node('p', 'Quote and quote source time: unavailable. This reader validates custody without a market price.', 'source'));
      const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Account and receipt details'));
      for (const [label, value] of [['Program', week.program], ['Week account', week.week_address], ['USDC mint', week.usdc_mint], ['Snapshot digest', week.snapshot_digest], ['Close receipt', week.receipt?.address], ['Active frame hash', week.receipt?.active_frame_hash]]) if (value) metadata.append(node('p', `${label}: ${value}`));
      article.append(metadata);
      if (week.rows.length) {
        const details = node('details', ''); details.append(node('summary', '24 burn chunks'));
        const table = node('table', ''); const thead = node('thead', ''); const tr = node('tr', '');
        for (const label of ['Chunk', 'State', 'Input USDC', 'Burned MORSE']) tr.append(node('th', label)); thead.append(tr); table.append(thead);
        const tbody = node('tbody', ''); for (const chunk of week.rows) { const row = node('tr', ''); for (const value of [String(chunk.index + 1), chunk.status, formatUnits(chunk.input_usdc_units), formatUnits(chunk.burned_morse_units)]) row.append(node('td', value)); tbody.append(row); } table.append(tbody);
        const scroll = node('div', '', 'table-scroll'); scroll.append(table); details.append(scroll); article.append(details);
      }
      body.append(article);
    }
  }
  function renderCollateral(report, bonds, slashes, node, now) {
    const title = (article, text, state) => { const heading = node('header', ''); heading.append(node('h3', text), node('span', state, 'state')); article.append(heading); };
    const source = (section, article) => {
      article.append(node('p', `Finalized context slot ${section.context_slot} · Source time ${time(section.source_time_unix)}. This bank applies to this section only.`, 'source'));
      const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Pinned identities and snapshot'));
      for (const key of ['judge', 'token', 'rewards', 'log_name', 'log_id', 'service_public_key', 'usdc_mint', 'morse_mint', 'snapshot_digest']) metadata.append(node('p', `${key}: ${section[key]}`));
      article.append(metadata);
    };
    const state = section => `${section.availability}${report.scope === 'configured-rpc' && isStale(report, section, now) ? ' · stale' : ''}${!section.code_current ? ' · code pin changed' : ''}`;
    const units = value => value === null ? 'Unavailable until settlement' : formatUnits(value);
    const grid = (article, fields) => { const dl = node('dl', ''); for (const [label, value] of fields) { const entry = node('div', ''); entry.append(node('dt', label), node('dd', value)); dl.append(entry); } article.append(dl); };
    if (report.bonds.availability !== 'available') bonds.append(node('p', `${report.bonds.availability}: no agreeing selected finalized bonds. Amounts unavailable; this is not evidence of no bond.`, 'empty'));
    else for (const row of report.bonds.rows) {
      const article = node('article', '', 'week bond-record'); title(article, row.kind === 'directory' ? 'Directory' : row.witness_id, `${row.status} · ${state(report.bonds)}`);
      grid(article, [['Asset', row.asset], ['Principal', units(row.principal_units)], ['Pending liability', units(row.pending_liability_units)], ['Vault balance', units(row.vault_balance_units)], ['Donation surplus', units(row.donation_surplus_units)], ['Pending record', units(row.pending_recorded_units)]]);
      article.append(node('p', row.status === 'slashed' ? 'The pending record remains historical; its effective liability is zero after this recorded slash.' : 'Principal, pending liability and donated surplus are separate amounts in the selected asset.', 'source'));
      article.append(node('p', `Recorded underwater marker: ${row.underwater_since_unix === '0' ? 'none' : time(row.underwater_since_unix)}. No price, grace eligibility or USD value is inferred.`, 'source'));
      article.append(node('p', `Bonded: ${time(row.bonded_at_unix)} · Unbond requested: ${row.unbond_at_unix === '0' ? 'none' : time(row.unbond_at_unix)} · Slashed: ${row.slashed_at_unix === '0' ? 'none' : time(row.slashed_at_unix)}`, 'source'));
      article.append(node('p', `Opposite-asset vault: ${row.opposite_asset_vault.availability === 'absent' ? 'absent in this bank' : `${units(row.opposite_asset_vault.balance_units)} ${row.asset === 'USDC' ? 'MORSE' : 'USDC'} (separate from this bond)`}.`, 'source'));
      const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Bond accounts')); for (const key of ['address', 'owner', 'mint', 'vault', 'public_key']) metadata.append(node('p', `${key}: ${row[key]}`)); article.append(metadata);
      source(report.bonds, article); bonds.append(article);
    }
    if (report.slashes.availability !== 'available') slashes.append(node('p', `${report.slashes.availability}: no agreeing selected finalized receipts. Amounts unavailable; this is not evidence of no slash.`, 'empty'));
    else {
      if (!report.slashes.receipts.length) slashes.append(node('p', 'No proof identifiers were selected. This is not a complete slash history.', 'empty'));
      for (const receipt of report.slashes.receipts) {
        const article = node('article', '', 'week slash-record'); title(article, `Proof ${receipt.proof_hash.slice(0, 12)}…`, `${receipt.status} · ${state(report.slashes)}`);
        for (const asset of receipt.assets) { article.append(node('h4', asset.asset)); grid(article, [['Slashed', units(asset.slashed_units)], ['Finder amount', units(asset.finder_units)], ['Directory included', units(asset.directory_slashed_units)]]); }
        article.append(node('p', 'Slashed amounts can include pending funds and donations. The assets are never added together. This receipt records onchain execution; the report does not independently reverify the fork proof.', 'source'));
        article.append(node('p', `Prepared: ${time(receipt.prepared_at_unix)} · Settled: ${receipt.status === 'settled' ? time(receipt.settled_at_unix) : 'not recorded'} · Verified signatures: ${receipt.verified_signatures}`, 'source'));
        const table = node('table', ''); const heading = node('tr', ''); for (const text of ['Witness', 'Asset', 'Principal', 'Slashed', 'Finder']) heading.append(node('th', text)); table.append(heading);
        for (const row of receipt.rows) { const tr = node('tr', ''); for (const text of [`${row.identity.slice(0, 12)}…`, row.asset, units(row.principal_units), units(row.slashed_units), units(row.finder_units)]) tr.append(node('td', text)); table.append(tr); }
        const scroll = node('div', '', 'table-scroll'); scroll.append(table); article.append(scroll);
        const metadata = node('details', '', 'metadata'); metadata.append(node('summary', 'Receipt accounts')); for (const key of ['address', 'proof_hash', 'finder', 'submitter', 'stage', 'deadline_ms']) metadata.append(node('p', `${key}: ${receipt[key]}`)); article.append(metadata);
        source(report.slashes, article); slashes.append(article);
      }
    }
  }
  globalThis.MorseNetworkReport = { validateReport, validatePublication, reportState, formatUnits, mount };
  if (typeof document !== 'undefined') mount(document, globalThis.MORSE_NETWORK_REPORT);
})();
