#!/usr/bin/env python3
"""Build a review-only proposal from immutable Git objects; never apply to source."""
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = "56148470ca80bc3a87fa31c158a1d7156c7223d8"
PREFIX = "mesh-private-messenger/packages/mobile-core/"
STATE = PREFIX + "mobile/group_invites_state.mpl"
MESSAGES = PREFIX + "mobile/messages.mpl"
SOURCES = [STATE, MESSAGES, PREFIX + "mobile/group_invites.mpl", PREFIX + "mobile/groups.mpl",
    PREFIX + "mobile/codec.mpl", PREFIX + "mobile/group_state.mpl",
    PREFIX + "mobile/transparency.mpl", PREFIX + "storage/keys.mpl",
    PREFIX + "tests/group_invitations.test.mpl",
    "mesh-private-messenger/packages/messenger-protocol/transparency/wire.mpl",
    "mesh-private-messenger/packages/messenger-protocol/transparency/merkle.mpl",
    "mesh-private-messenger/packages/messenger-protocol/protocol/v1.mpl"]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def replace_once(text, before, after):
    assert text.count(before) == 1, before[:120]
    return text.replace(before, after, 1)

original = {}
for name in SOURCES:
    data = subprocess.check_output(["git", "show", BASE + ":" + name], cwd=ROOT)
    original[name] = data.decode()
    target = OUT / "base" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)

state = original[STATE]
state = replace_once(state, "from Mobile.Types import MobileGroupKeyPackage",
    "from Mobile.Types import MobileGroupKeyPackage, MobileTransparencyView")
state = replace_once(state,
    "pub fn invitation_blob(values :: List<GroupInvitation>, key :: borrow StorageKey) -> Bytes!String do",
    "pub fn invitation_plaintext(values :: List<GroupInvitation>) -> Bytes!String do")
state = replace_once(state,
    '  seal_local(encode_output_list(records)?, key, local_context("group-invitations/v1")?)\nend',
    '''  encode_output_list(records)
end

pub fn invitation_blob(values :: List<GroupInvitation>, key :: borrow StorageKey) -> Bytes!String do
  seal_local(invitation_plaintext(values)?, key, local_context("group-invitations/v1")?)
end''')

start = state.index("fn receive_control(")
stop = state.index("\n## Invalid authenticated controls", start)
old_control = state[start:stop]
body_start = old_control.index("  if inner.message_type == 3 do")
split = old_control.index("    if previous.state == 3 do")
preparation = old_control[body_start:split]
preparation = preparation.replace("return Ok(values)", "return Ok(InvitationValues(values))")
preparation = preparation.replace("Ok(List.append(values,", "Ok(InvitationValues(List.append(values,")
preparation = replace_once(preparation, "      }))", "      })))")
finish = old_control[split:]
finish = replace_once(finish,
    "      let view = load_transparency_view(path, key)?",
    '''      let view = case current_view do
        Some(value) -> Ok(value)
        None -> Err("group_transparency_unverified")
      end?''')
finish = finish.replace("key_package: List.get(p, 2)", "key_package: key_package")
finish = "\n".join("  " + line if line else line for line in finish.splitlines()) + "\n"
finish = finish[:-len("    end\n  end\n")] + "    end\n  end\nend\n"
replacement = '''pub type InvitationControl do
  InvitationValues(values :: List<GroupInvitation>)
  InvitationAcceptance(values :: List<GroupInvitation>,
    previous :: GroupInvitation,
    group_id :: Bytes,
    package :: MobileGroupKeyPackage,
    key_package :: Bytes)
end

pub fn prepare_invitation_control(values :: List<GroupInvitation>,
  now :: U64,
  local :: ClientProfile,
  username :: String,
  inner :: InnerEnvelope) -> InvitationControl!String do
''' + preparation + '''    Ok(InvitationAcceptance(values, previous, group_id, package, List.get(p, 2)))
  end
end

pub fn invitation_control_requires_view(prepared :: InvitationControl) -> Bool do
  case prepared do
    InvitationValues(_) -> false
    InvitationAcceptance(_, previous, _, _, _) -> previous.state == 3
  end
end

pub fn finish_invitation_control(prepared :: InvitationControl,
  local :: ClientProfile,
  inner :: InnerEnvelope,
  current_view :: Option<MobileTransparencyView>) -> List<GroupInvitation>!String do
  case prepared do
    InvitationValues(values) -> Ok(values)
    InvitationAcceptance(values, previous, group_id, package, key_package) -> do
''' + finish + '''
fn receive_control(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  username :: String,
  inner :: InnerEnvelope) -> List<GroupInvitation>!String do
  let values = load_invitations(path, key)?
  let now = current_time()?
  let prepared = prepare_invitation_control(values, now, local, username, inner)?
  let view = if invitation_control_requires_view(prepared) do
    Some(load_transparency_view(path, key)?)
  else
    None
  end
  finish_invitation_control(prepared, local, inner, view)
end
'''
state = state[:start] + replacement + state[stop:]
state = state.replace("fn validate_control(inner", "pub fn invitation_control_valid(inner")
state = state.replace("case validate_control(inner)", "case invitation_control_valid(inner)")

messages = original[MESSAGES]
messages = replace_once(messages,
    "from Mobile.GroupInvitesState import received_invitation_writes",
    '''from Mobile.GroupInvitesState import (
  invitation_control_valid,
  load_invitations,
  prepare_invitation_control,
  invitation_control_requires_view,
  finish_invitation_control,
  invitation_plaintext
)
from Mobile.Transparency import load_transparency_view''')
messages = replace_once(messages,
    "from Storage.Keys import one_time_prekey_label, platform_key",
    "from Storage.Keys import one_time_prekey_label, platform_key, local_context, seal_local")
assert messages.count("received_invitation_writes(") == 2
messages = messages.replace("received_invitation_writes(", "authenticated_invitation_writes(")
boundary = '''fn authenticated_invitation_writes(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  username :: String,
  inner :: InnerEnvelope) -> Result<(List<String>, List<Bytes>), String> do
  let valid = Result.unwrap_or(invitation_control_valid(inner), false)
  if !declassify(valid,
    "private initial or ratchet receive after peer identity conversation recipient and block checks releases only bounded invitation framing acceptance before invitation storage access and pruning; body fields and parser errors remain private") do
    return Ok(([], []))
  end
  let values = load_invitations(path, key)?
  let now = current_time()?
  let prepared = prepare_invitation_control(values, now, local, username, inner)
  let renewal = case prepared do
    Ok(value) -> invitation_control_requires_view(value)
    Err(_) -> false
  end
  let view = if declassify(renewal,
    "private authenticated invitation receive releases only whether successful control preparation found an existing state3 acceptance requiring the current transparency view; reference membership is exposed only through this decision and identifiers key packages and later authorization decisions remain private") do
    Some(load_transparency_view(path, key)?)
  else
    None
  end
  let encoded = case prepared do
    Err(error) -> Err(error)
    Ok(value) -> case finish_invitation_control(value, local, inner, view) do
      Err(error) -> Err(error)
      Ok(updated) -> invitation_plaintext(updated)
    end
  end
  if !declassify(Result.is_ok(encoded),
    "private authenticated invitation receive releases only successful pure control completion and invitation encoding before context construction and one local seal; exact failure payloads and encoded invitation records remain private and failed preparation performs no context construction or seal") do
    let error = case encoded do
      Err(value) -> value
      Ok(_) -> "invalid_group_invitation"
    end
    return Err(error)
  end
  let plaintext = Result.unwrap_or(encoded, Bytes.empty())
  let context = local_context("group-invitations/v1")?
  let blob = seal_local(plaintext, key, context)?
  Ok((["group-invitations/v1"], [blob]))
end

'''
messages = replace_once(messages,
    "pub fn receive_initial_message(request :: MobileReceiveRequest)",
    boundary + "pub fn receive_initial_message(request :: MobileReceiveRequest)")

updated = {STATE: state, MESSAGES: messages}
patch = ""
for name, text in updated.items():
    target = OUT / "proposed" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    patch += "".join(difflib.unified_diff(original[name].splitlines(True), text.splitlines(True),
        fromfile="a/" + name, tofile="b/" + name))
(OUT / "invitation-private-boundary.patch").write_text(patch)

sites = []
for expression in ("declassify(valid,", "declassify(renewal,", "declassify(Result.is_ok(encoded),"):
    offset = messages.index(expression, messages.index("fn authenticated_invitation_writes("))
    reason_start = messages.index('"', offset)
    reason_end = messages.index('"', reason_start + 1)
    sites.append({"file": MESSAGES, "module": "Mobile.Messages", "kind": "declassify",
        "function": "authenticated_invitation_writes", "visibility": "private",
        "expression": expression, "line": messages.count("\n", 0, offset) + 1,
        "column": offset - messages.rfind("\n", 0, offset),
        "reason": messages[reason_start + 1:reason_end], "domain": [False, True]})
(OUT / "proposed-sites.json").write_text(json.dumps({"status": "unapproved source proposal; not compiler output or inventory",
    "baseline": BASE, "sites": sites}, indent=2) + "\n")

manifest = {"baseline": BASE, "source_origin": "immutable git show <baseline>:<path>; no mutable VO source reads",
    "base_sha256": {name: sha(text.encode()) for name, text in original.items()},
    "proposed_sha256": {name: sha(text.encode()) for name, text in updated.items()},
    "patch_sha256": sha(patch.encode()), "compiler_run": False, "runtime_run": False,
    "applied_to_worktree": False}
(OUT / "source-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"patch": str(OUT / "invitation-private-boundary.patch"),
    "new_release_sites": len(sites), "base": BASE}, indent=2))
