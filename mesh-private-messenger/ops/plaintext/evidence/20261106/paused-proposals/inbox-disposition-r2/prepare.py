from pathlib import Path
import difflib,hashlib,json,re,subprocess
root=Path.cwd(); out=root/'.morse/decoded-body-labels/inbox-disposition-r2/proposal';base='0d6826b5d02e3439d93568ecc1d6fa996135a505';prefix='mesh-private-messenger/packages/mobile-core/';rel=prefix+'mobile/inbox.mpl'
sha=lambda data:hashlib.sha256(data).hexdigest()
read=lambda path:subprocess.check_output(['git','show',base+':'+path])
files=['mobile/inbox.mpl','mobile/inbox_state.mpl','mobile/groups.mpl','mobile/types.mpl','mobile/requests.mpl','mobile/mailbox_sync.mpl','mobile/profile.mpl','mobile/messages.mpl','mobile/group_invites_state.mpl','mobile/gossip.mpl','mobile_core.mpl','mesh.toml','tests/inbox_poison.test.mpl','tests/header_receive.test.mpl','tests/initial_session.test.mpl']
inputs={}
for part in files:
 path=prefix+part;data=read(path);p=out/'base'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);inputs[path]=sha(data)
original=read(rel).decode();parent=Path('/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-f9098070')/rel
assert sha(parent.read_bytes())==inputs[rel], 'parent Inbox differs from instructed pin'
assert original.count('error == "view_once_reference_refused"')==1
before='  let decision = acknowledge_delivery(database_path, profile, outer, encoded)\n'
reason='private local mailbox settlement releases only the existing routing and receive disposition, including decoded-content local-state and unauthenticated rejection: applied permanent rejection or unknown kind permits ACK; only direct unfinished selection defers without changing attempts or evaluating age-out on this pass; other routing direct and group outcomes follow existing retry and wall-clock aging; bodies exact errors and unrelated caller control remain private'
after='''  let observed = acknowledge_delivery(database_path, profile, outer, encoded)
  let disposition = case observed do
    1 -> 1
    2 -> 2
    _ -> 0
  end
  let decision = declassify(disposition,
    "'''+reason+'''")
'''
assert original.count(before)==1;proposed=original.replace(before,after)
assert proposed.replace(after,before)==original
path=out/'proposed'/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(proposed)
patch=''.join(difflib.unified_diff(original.splitlines(True),proposed.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel));patchfile=out/'inbox-disposition-r2.patch';patchfile.write_text(patch)
cmd=['git','apply','--check','--unsafe-paths','--directory='+str(out/'base'),str(patchfile)]
r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr

def members(text,name):
 body=re.search(r'(?m)^(?:pub )?fn '+name+r'\(.*?\nend',text,re.S)[0]
 return re.findall(r'error == "([^"]+)"',body)
D=members(original,'permanent_direct_delivery_error');H=members(original,'header_selection_unfinished');G=members(read(prefix+'mobile/groups.mpl').decode(),'permanent_group_delivery_error')
assert len(D)==22 and len(H)==3 and len(G)==13 and not set(D)&set(H)
matrix={'sets':{'D_direct_permanent':D,'H_direct_unfinished':H,'G_group_permanent':G},'rows':[
 {'route':'delivery_kind Err(e)','decision':'1 if e in D, otherwise0; H never consulted','receive_invoked':False},
 {'route':'delivery_kind Ok(0)','decision':1,'receive_invoked':False,'meaning':'unknown opened sealed packet kind'},
 {'route':'delivery_kind Ok(3), GroupReceiveApplied','decision':1,'receive_invoked':'group'},
 {'route':'delivery_kind Ok(3), error in G / GroupReceiveRejected','decision':1,'receive_invoked':'group'},
 {'route':'delivery_kind Ok(3), error outside G / GroupReceiveRetry','decision':0,'receive_invoked':'group','includes':H,'note':'account_state_changed guard failure retries, never direct deferral'},
 {'route':'other successful kind, direct Ok','decision':1,'receive_invoked':'initial if kind1, otherwise ratchet'},
 {'route':'other successful kind, direct error in D','decision':1,'precedence':'D wins over H, including any future overlap'},
 {'route':'other successful kind, direct error outside D but in H','decision':2},
 {'route':'other successful kind, direct error outside D and H','decision':0},
 {'route':'hypothetical acknowledge_delivery Int other than1 or2','decision':0,'note':'same previous else retry branch; acknowledge currently returns only0/1/2'}],
 'before_settlement':['Stored profile load occurs before full batch decode','Malformed member rejected by batch decoding: no per-envelope settlement site','Later canonical_outer failure skips that member without ACK/attempt/highest update; do not equate every malformed wire with D invalid_outer_envelope'],
 'state_effects':{'2':'ACK IDs/attempt bytes/first-attempt timestamp unchanged, set_aside=true, highest=max sequence; no age-out evaluation during this pass. Header routing may already have persisted its own cursor.','1':'Append envelope ID, remove retry record, preserve earlier set_aside, highest=max sequence. ACK is eligibility, not proof of display/history/contact authenticity.','0':'Use fixed batch now and prior attempts. ACK/remove only when current try reaches16 and original first attempt is at least86400000ms old; otherwise increment/saturate count, retain first timestamp, set_aside. 256-record bound/eviction unchanged.'},
 'wall_clock':'Deferral does not pause age or reset first-attempt time. Retry -> long direct deferral -> retry may immediately age out on resumed retry if both thresholds hold. Routing/group H-string failures take ordinary0 path.',
 'after_settlement':['Any set_aside -> cursor highest canonical-settled sequence, including later successes; otherwise0. Empty batch resets cursor.','Prepare/seal/store attempts+cursor -> clock -> direct expiry -> group expiry -> gossip flush -> optional key open/time/sign ACK. Earlier error wins, earlier durable writes are not rolled back.','process_delivery_batch returns signed ACK bytes; MailboxSync posts later. ACK transport failure does not roll back receive.'],
 'first_error_examples':['Direct optional safety framing invalid_store_request and safety length invalid_safety_number retry; required-field invalid_sync_payload ACKs; optional tail parsing can win over later required-field validation.','Blocked receive commit failure wins over subsequent blocked_message permanent rejection.','Well-framed invitation enters existing loader/view and may retry on storage failure; malformed control may be ignored and ACK after caller commit.','Group earlier snapshot/storage error wins over later malformed payload or crypto error; account_state_changed guard retry remains0.','Preserve parent view_once_reference_refused permanent membership and its guard before later contact/gossip/invitation work.','Attempt bookkeeping or final batch persistence/expiry/gossip/signature errors escape, not classified by this site.']}
(out/'classification-matrix.json').write_text(json.dumps(matrix,indent=2)+'\n')
review=Path('/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-f9098070/.morse/continuation-20261106/inbox-disposition-review-r1/review.md')
d={'status':'R2_PROPOSAL_UNAPPLIED_UNCOMPILED_UNAPPROVED','base':base,'parent_inbox_verified_equal_to_base':True,'base_sha256':inputs[rel],'proposed_sha256':sha(proposed.encode()),'patch_sha256':sha(patch.encode()),'source':rel,'review':{'path':str(review),'sha256':sha(review.read_bytes()),'verdict':'REQUEST_CHANGES accepted'},'r1':{'patch_sha256':'3be7359980ac07e479cde48fe2d6bdc0948d01db19c7213e4f6e1fcbe2996f97','preserved':True},'site':{'function':'private settle_delivery','line':proposed[:proposed.index('  let decision = declassify')].count('\n')+1,'domain':[0,1,2],'reason':reason,'new_sites':1},'changes_from_r1':{'source_base':'Actual parent0d6826b; retain view_once_reference_refused and every other byte outside one settlement binding.','policy_description':['Covers routing failure and unknown-kind paths without actual receive','Explicitly permits decoded-content/local-state-dependent and unauthenticated rejection classifications','Only direct H nonpermanent failures defer; routing/group H strings retry','Deferral skips charging and age-out on that pass only; wall-clock time and original retry timestamp continue'],'runtime_semantics':'No intended runtime behavior change. Same acknowledge call, pure1/2/default0 normalization and single proposed release. No effects moved. Parent D/G/H sets unmodified.'},'authority':'Private settle_delivery called only by private process_deliveries after canonical_outer, from public process_delivery_batch using stored local profile. Wire batch is caller supplied; neither mailbox-fetch origin nor peer authentication is established for every route. Classifications originate from actual routing/receive calls, not caller Int/error/decoded-envelope authority. This is explicit local mailbox settlement policy.','observable_scope':'Per reached invocation0/1/2 permits existing ACK-ID selection, retry bookkeeping and cursor behavior; can reveal content/error distinctions, local-state and repeated observations. No lifetime query budget or content noninterference claim.','not_authorized':['Arbitrary body/error/Result/metadata payload release','Earlier receive/gossip/invitation effects','Unrelated caller PC/private selection','New public classifier disclosure','Sibling trust, restored-session provenance or VO completion','Inventory, transplant, adoption, deployment'], 'sources':inputs,'applycheck':{'argv':cmd,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr},'artifact_checks':{'strict_single_hunk_reconstruction':True,'parent_view_once_permanent_retained':True,'exact_D_H_G_counts':[len(D),len(H),len(G)]},'qualification':'Only source/apply/hash checks here. Baseline proof preparation in ../proof is separate and does not qualify this proposed release. Final candidate controls unrun until auth+VO ownership and policy gates close.'}
(out/'proposal.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({k:d[k] for k in ('base','base_sha256','proposed_sha256','patch_sha256')}));print('D/H/G',len(D),len(H),len(G))
