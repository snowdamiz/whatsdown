window.addEventListener('DOMContentLoaded', async () => {
  const report = { result: 'failed', post_message_only: false };
  try {
    const origin = __MORSE_PROBE_ORIGIN__;
    const violations = [];
    document.addEventListener('securitypolicyviolation', (event) => violations.push(event.effectiveDirective));
    let protocolFetchBlocked = false;
    try { await fetch('ipc://localhost/probe_echo', { method: 'POST', body: '{}' }); }
    catch { protocolFetchBlocked = true; }
    if (!protocolFetchBlocked) throw Error('CSP permits fetch-based IPC');
    report.protocol_fetch_blocked = true;
    await fetch(`${origin}/fetch`).then(() => { throw Error('fetch escaped'); }, () => {});
    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.onload = () => reject(Error('XHR escaped')); xhr.onerror = resolve;
      xhr.open('POST', `${origin}/xhr`); xhr.send('synthetic');
    });
    await new Promise((resolve, reject) => {
      try {
        const socket = new WebSocket(`${origin.replace('http:', 'ws:')}/socket`);
        socket.onopen = () => reject(Error('WebSocket escaped')); socket.onerror = resolve;
      } catch { resolve(); }
    });
    await new Promise((resolve, reject) => {
      const image = new Image(); image.onload = () => reject(Error('image escaped')); image.onerror = resolve; image.src = `${origin}/image`;
    });
    const frame = document.createElement('iframe'); frame.name = 'synthetic-leak-target'; frame.srcdoc = '<html></html>'; frame.sandbox = 'allow-forms'; document.body.append(frame);
    const form = document.createElement('form'); form.method = 'POST'; form.action = `${origin}/form`; form.target = frame.name; document.body.append(form); form.submit();
    window.open(`${origin}/popup`);
    window.location.assign(`${origin}/navigate`);
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (!violations.includes('connect-src') || !violations.includes('form-action') || !violations.includes('img-src')) throw Error('missing browser CSP enforcement');
    report.browser_csp_enforced = true;
    Object.defineProperty(window, 'fetch', { value: undefined, configurable: false, writable: false });
    Object.defineProperty(window, 'XMLHttpRequest', { value: undefined, configurable: false, writable: false });
    Object.defineProperty(window, 'WebSocket', { value: undefined, configurable: false, writable: false });
    const all = new Uint8Array(65578); all[0] = 99; all[65577] = 88;
    for (let i = 1; i < all.length - 1; i++) all[i] = i % 256;
    const exact = all.subarray(1, all.length - 1);
    const response = await window.__TAURI_INTERNALS__.invoke('probe_echo', exact, { headers: { 'X-Morse-Probe': 'binary' } });
    const returned = response instanceof ArrayBuffer ? new Uint8Array(response) : Uint8Array.from(response);
    if (returned.length !== exact.length || returned.some((v, i) => v !== exact[i])) throw Error('binary response changed');
    for (const invalid of [[-1], [256], [true], [1.5], [[1]], { 0: 1 }]) {
      let refused = false;
      try { await window.__TAURI_INTERNALS__.invoke('probe_echo', invalid, { headers: { 'X-Morse-Probe': 'binary' } }); }
      catch (error) { refused = String(error) === 'invalid_probe_binary'; }
      if (!refused) throw Error('noncanonical byte payload accepted');
    }
    const channel = await new Promise(async (resolve, reject) => {
      const id = window.__TAURI_INTERNALS__.transformCallback((event) => {
        if ('message' in event) resolve(event.message);
      });
      try {
        await window.__TAURI_INTERNALS__.invoke('probe_channel', { channel: { __TAURI_TO_IPC_KEY__: () => `__CHANNEL__:${id}` } });
      } catch (error) { reject(error); }
    });
    if (channel.length !== 65576 || channel.some((v) => v !== 42)) throw Error('channel response changed');
    report.large_channel_without_fetch = true;
    report.noncanonical_binary_rejected = true;
    report.post_message_only = true;
    report.bytes = exact.length;
    report.result = 'passed';
  } catch (error) { report.error = String(error); }
  await window.__TAURI_INTERNALS__.invoke('probe_finish', { report });
});
