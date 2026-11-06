// Native IPC/network fixtures for real rendered purchase and signup flows.
export function installCreditFixture({ mode }) {
      const text = value => [...new TextEncoder().encode(value)];
      const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
      const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
      const list = (...fields) => vectors(u32(fields.length), ...fields);
      const credit = (...fields) => [...u32(fields.length), ...vectors(...fields)];
      const parts = bytes => {
        const input = Uint8Array.from(bytes); const view = new DataView(input.buffer);
        let offset = 4; const values = [];
        for (let index = 0; index < view.getUint32(0); index++) {
          const length = view.getUint32(offset); offset += 4;
          values.push([...input.slice(offset, offset + length)]); offset += length;
        }
        return values;
      };
      let id = Array(32).fill(7);
      const signupMode = mode.startsWith('signup');
      let draft = Number(localStorage.getItem('signup-proof-draft') ?? (mode === 'signup' ? -1 : signupMode ? 1 : 0));
      let signupStatus = Number(localStorage.getItem('signup-proof-status') ?? (mode === 'signup' || mode.startsWith('signup-free') ? -1 : 0));
      let cancelled = false;
      let username = localStorage.getItem('signup-proof-username') || 'alice';
      const profile = () => vectors(text(username), Array(32).fill(1), Array(16).fill(1), []);
      const saveSignup = () => { localStorage.setItem('signup-proof-draft', draft); localStorage.setItem('signup-proof-status', signupStatus); localStorage.setItem('signup-proof-username', username); };
      const signupPlan = () => credit(text('\u0001MCS'), id, [signupStatus], Array(8).fill(0), text('https://edge.example'), text(signupStatus === 0 ? '/v1/credits/signup' : ''), signupStatus === 0 ? [88, 99] : []);
      const journal = JSON.parse(localStorage.getItem('credits-proof-journal') || (mode === 'expired' ? '{"stage":1,"credits":100}' : '{"stage":-1,"credits":500}'));
      const save = () => localStorage.setItem('credits-proof-journal', JSON.stringify(journal));
      let walletCreated = false;
      const plan = () => credit(text('\u0002MCP'), id, [journal.stage], [journal.credits >>> 8, journal.credits & 255], Array(8).fill(0),
        text('https://edge.example'), text(journal.stage === 0 ? '/v1/credits/quote' : journal.stage === 2 ? '/v1/credits/issue' : ''),
        journal.stage === 0 ? [11, 22] : journal.stage === 2 ? [33, 44] : [], journal.stage > 0 ? [9] : [], [journal.asset ?? 0]);
      window.creditsUITest = { calls: [], requests: [], failIssue: true, failSignup: true, freeConflict: mode === 'signup-free-conflict', balanceAvailable: 100, badDraft: mode === 'signup-bad-state' && !localStorage.getItem('signup-proof-readable'), witnessed: false, cancelPay: true, opened: [], copied: [] };
      window.open = url => { window.creditsUITest.opened.push(String(url)); return null; };
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: async text => window.creditsUITest.copied.push(text) } });
      window.isTauri = true;
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback: () => {},
        invoke: async (command, args, options) => {
          if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
          if (command === 'database_path') return '/test/credits.db';
          if (command === 'appearance') return 'dark';
          if (command === 'mailbox_connect' || command === 'mailbox_disconnect') return;
          if (command === 'credit_open_payment') { if (journal.asset === 2) { journal.stage = 2; save(); } window.creditsUITest.opened.push(journal.asset === 2 ? 'lightning:lnbcrt1verifiedinvoice' : 'solana:verified-owner?amount=0.125000000'); return; }
          if (command === 'binary_request') {
            const route = options.headers['X-Service-Url'];
            if (!route.startsWith('https://edge.example/v1/credits/')) {
              window.creditsUITest.requests.push({ route, body: [...args] });
              if (mode.startsWith('signup-free') && window.creditsUITest.freeConflict && route.endsWith('/v1/devices/register')) { window.creditsUITest.freeConflict = false; return [1, 153]; }
              if (mode.startsWith('signup-free') && (route.endsWith('/v1/devices/register') || route.endsWith('/v2/devices/resolve') || route.endsWith('/v1/prekeys/one-time/batch'))) return [0, 200, 1];
              throw Error('Offline fixture');
            }
            window.creditsUITest.requests.push({ route, body: [...args] });
            if (route.endsWith('/issue') && window.creditsUITest.failIssue) throw Error('unknown network outcome');
            if (route.endsWith('/signup-policy')) return [0, 200, ...Array(88).fill(42)];
            if (route.endsWith('/signup') && window.creditsUITest.failSignup) throw Error('unknown signup outcome');
            return [0, 200, 1, 2, 3];
          }
          if (command === 'wallet_invoke') {
            const operation = options.headers['X-Wallet-Operation'];
            window.creditsUITest.calls.push({ wallet: operation, args: [...args] });
            if (operation === '2') { if (!walletCreated) throw Error('wallet_not_created'); return Array(32).fill(1); }
            if (operation === '1') { walletCreated = true; return Array(32).fill(1); }
            if (operation === '5') {
              if (!walletCreated) throw Error('wallet_not_created');
              if (window.creditsUITest.cancelPay) { window.creditsUITest.cancelPay = false; throw Error('wallet_native_error_4'); }
              const fields = parts(args);
              if (fields.length !== 2 || fields[1].some(value => value !== 7)) throw Error('invalid_wallet_request');
              journal.stage = 2; save(); window.creditsUITest.failIssue = false;
              return credit(text('\u0001MWR'), id, [1], Array(64).fill(8));
            }
            throw Error('Unexpected wallet operation');
          }
          const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
          if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
          if (symbol?.startsWith('mesh_messenger_credit_')) {
            window.creditsUITest.calls.push({ symbol, args: [...args] });
            if (mode === 'disabled') throw Error('credits_disabled');
            if (symbol.endsWith('_signup_policy_online')) {
              window.creditsUITest.requests.push({ route: 'https://edge.example/v1/credits/signup-policy', body: [], native: true });
              return credit(text('\u0002SPV'), [1], [1], [18], [22], [0, 20], Array(8).fill(0), Array(88).fill(42));
            }
            if (symbol.endsWith('_action_continue')) {
              const selector = parts(args)[2][0];
              if (!cancelled && signupStatus === 0) {
                const route = 'https://edge.example/v1/credits/' + (selector === 2 ? 'reconcile' : selector === 1 ? 'signup' : 'retention');
                window.creditsUITest.requests.push({ route, body: [88, 99], native: true });
                if (selector === 1 && window.creditsUITest.failSignup) throw Error('unknown signup outcome');
                if (mode === 'signup-cancel') { signupStatus = -1; draft = 1; cancelled = true; }
                else { signupStatus = 1; draft = 3; }
                saveSignup();
              }
              if (selector === 2) return credit(text('\u0001MCE'), id, [cancelled ? 2 : signupStatus], [4], Array(8).fill(0), text('https://edge.example'), [], []);
              return signupPlan();
            }
            if (symbol.endsWith('_signup_policy_view')) return credit(text('\u0001SPV'), [1], [1], [18], [22], [0, 20], Array(8).fill(0));
            if (symbol.endsWith('_signup_policy')) return credit(text('\u0001MCY'), text('https://edge.example'), text('/v1/credits/signup-policy'), []);
            if (symbol.endsWith('_signup_recover')) { if (signupStatus < 0) throw Error('credit_signup_not_started'); return signupPlan(); }
            if (symbol.endsWith('_signup')) { signupStatus = 0; saveSignup(); return signupPlan(); }
            if (symbol.endsWith('_action_recovery')) return credit(text('\u0001MCE'), id, [cancelled ? 2 : signupStatus], [4], Array(8).fill(0), text('https://edge.example'), text(!cancelled && signupStatus === 0 ? '/v1/credits/reconcile' : ''), !cancelled && signupStatus === 0 ? [88, 99] : []);
            if (symbol.endsWith('_receipt')) {
              if (mode === 'signup-cancel') { signupStatus = -1; draft = 1; cancelled = true; } else { signupStatus = 1; draft = 3; }
              saveSignup(); return [];
            }
            if (symbol.endsWith('_balance')) return credit(text('\u0003MCB'), ...[signupMode ? window.creditsUITest.balanceAvailable : journal.stage === 3 ? journal.credits : 0, 0, signupStatus === 0 && signupMode ? 20 : 0, 0, journal.stage >= 0 && journal.stage < 3 ? 1 : 0].map(u32), [1], [mode.startsWith('lightning') ? 2 : 255]);
            if (symbol.endsWith('_purchases')) return credit(text('\u0001MCL'), ...(journal.stage >= 0 ? [id] : []));
            if (symbol.endsWith('_discovery')) return credit(text('\u0001MCD'), text('https://edge.example'), text('/v1/credits/issuer'), [1]);
            if (symbol.endsWith('_admit') || symbol.endsWith('_discover_online')) return [];
            if (symbol.endsWith('_purchase_continue')) {
              if (journal.stage === 0 || journal.stage === 2) {
                const route = 'https://edge.example/v1/credits/' + (journal.asset === 2 ? 'lightning/' : '') + (journal.stage === 0 ? 'quote' : 'issue');
                window.creditsUITest.requests.push({ route, body: journal.stage === 0 ? [11, 22] : [33, 44], native: true });
                if (journal.stage === 2 && window.creditsUITest.failIssue) throw Error('unknown network outcome');
                journal.stage = journal.stage === 0 ? 1 : mode === 'lightning-canceled' ? 4 : 3; save();
              }
              return plan();
            }
            if (symbol.endsWith('_prepare') || symbol.endsWith('_prepare_again')) {
              if (symbol.endsWith('_prepare_again')) id = Array(32).fill(8);
              const fields = parts(args); journal.credits = new DataView(Uint8Array.from(fields[1]).buffer).getUint32(0); journal.asset = fields[2][0];
              journal.stage = 0; save(); return plan();
            }
            if (symbol.endsWith('_quote')) { journal.stage = 1; save(); return plan(); }
            if (symbol.endsWith('_payment_url')) {
              if (mode === 'expired' && id[0] === 7) throw Error('credit_quote_expired');
              return text(journal.asset === 2 ? 'lightning:lnbcrt1verifiedinvoice' : 'solana:verified-owner?amount=0.125000000');
            }
            if (symbol.endsWith('_payment') || symbol.endsWith('_payment_signature')) { journal.stage = 2; save(); return plan(); }
            if (symbol.endsWith('_finalize')) { journal.stage = 3; save(); return plan(); }
            if (symbol.endsWith('_recover')) return plan();
            throw Error(`Unexpected credit IPC: ${symbol}`);
          }
          if (symbol === 'mesh_messenger_presentation_save') {
            const input = Uint8Array.from(args); const view = new DataView(input.buffer); let offset = 0; let field;
            for (let index = 0; index < 3; index++) { const length = view.getUint32(offset); offset += 4; field = [...input.slice(offset, offset + length)]; offset += length; }
            return field;
          }
          if (symbol === 'mesh_messenger_signup_draft_state') return window.creditsUITest.badDraft ? [7] : [draft];
          if (symbol === 'mesh_messenger_create_signup_draft') {
            const input = Uint8Array.from(args); const view = new DataView(input.buffer); const first = view.getUint32(0);
            const size = view.getUint32(first + 4); username = new TextDecoder().decode(input.slice(first + 8, first + 8 + size));
            draft = 1; saveSignup(); window.creditsUITest.calls.push({ symbol, args: [...args] }); return profile();
          }
          if (symbol === 'mesh_messenger_signup_draft_rename') { username = new TextDecoder().decode(Uint8Array.from(parts(args)[1])); window.creditsUITest.witnessed = false; saveSignup(); return profile(); }
          if (symbol === 'mesh_messenger_directory_resolve') { if (mode.startsWith('signup-free')) window.creditsUITest.witnessed = true; return [1]; }
          if (symbol === 'mesh_messenger_verify_transparency' && mode.startsWith('signup-free')) { window.creditsUITest.witnessed = true; return [1]; }
          if (symbol === 'mesh_messenger_signup_draft_free_complete') {
            if (!window.creditsUITest.witnessed) throw Error('signup_witness_required');
            draft = 3; saveSignup(); window.creditsUITest.calls.push({ symbol, args: [...args] }); return profile();
          }
          if (symbol === 'mesh_messenger_signup_draft_free') { draft = 2; saveSignup(); return profile(); }
          if (symbol === 'mesh_messenger_directory_register') {
            window.creditsUITest.calls.push({ symbol, args: [...args] });
            if (draft === 1) throw Error('paid_signup_draft_pending');
            if (mode.startsWith('signup-free') && window.creditsUITest.freeConflict) {
              window.creditsUITest.freeConflict = false;
              throw Error('registration_refused');
            }
            return [1,68,82,71,0,64,0];
          }
          if (symbol === 'mesh_messenger_devices_renew') return [1,68,78,82,0,0,0,0];
          if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
          if (symbol === 'mesh_messenger_register_signup_policy') { window.creditsUITest.calls.push({ symbol, args: [...args] }); return []; }
          if (symbol === 'mesh_messenger_load_profile') { if (draft < 0) throw Error('local_state_not_found'); return profile(); }
          if (symbol === 'mesh_messenger_anchor_check') return list(...['off', '0', '0', '0', '0'].map(text));
          if (symbol === 'mesh_messenger_transparency_fork') return [];
          if (['mesh_messenger_list_conversations', 'mesh_messenger_group_list', 'mesh_messenger_group_invitations', 'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
          if (symbol === 'mesh_messenger_resolve_plan') return list(list(text('/v2/devices/resolve'), []));
          if (symbol === 'mesh_messenger_replenish_prekeys' && mode.startsWith('signup-free')) return [];
          if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
          if (symbol === 'mesh_messenger_register_request') window.creditsUITest.calls.push({ symbol, args: [...args] });
          if (['mesh_messenger_presentation_load', 'mesh_messenger_journal_load', 'mesh_messenger_journal_save', 'mesh_messenger_journal_load_bound', 'mesh_messenger_journal_save_bound', 'mesh_messenger_register_request', 'mesh_messenger_mailbox_fetch', 'mesh_messenger_directory_entry'].includes(symbol)) return [];
          throw Error(`Unexpected IPC: ${symbol || command}`);
        },
      };

}
