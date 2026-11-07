from pathlib import Path
import shutil, hashlib, json, difflib
root=Path(__file__).resolve().parent
proof=root.parent/'inbox-disposition-r2/proof'
source=proof/'focused-tests'
variant=root/'stages'
assert not variant.exists()
shutil.copytree(source,variant,ignore=shutil.ignore_patterns('.mesh','build'))
# Existing compiler harness already rewrites only manifests, never production modules.
p=variant/'tests/header_receive.test.mpl'
original=p.read_text()
start=original.index('fn pending_and_cas()')
end=original.index('\ntest(',start)
body=original[start:end].replace('fn pending_and_cas()','fn diagnostic_stage(stop :: Int)',1)
markers=[
('after_start_before_initial', '  assert_received_fixture(Bytes.secure_equals(receive_initial_message'),
('after_initial_before_update', '  update_conversation_export(request(['),
('after_update_before_send', '  let message = send_message('),
('after_send_before_aliases', '  add_aliases(fixture.bob_path, 16)?'),
('after_aliases_before_packet', '  let outer = canonical_outer(message)?'),
('after_packet_before_route', '  # A real earlier profile'),
('after_held_cursors_before_batch', '  let attempts_before = load_delivery_attempts'),
('after_batch_before_assertions', '  assert(Bytes.length(first) == 0)'),
('after_cursor_assertions_before_cas', '  # Read/probe succeeds'),
('after_cas_before_history', '  # An independent authenticated history'),
('after_history_before_final_delivery', '  let result = ack(process_delivery_batch(batch)?)?'),
('after_final_delivery_before_replay', '  # The exact same encrypted packet')]
for i,(_,marker) in enumerate(markers,1):
 assert body.count(marker)==1,marker
 body=body.replace(marker,f'  if stop == {i} do\n    return Ok(true)\n  end\n'+marker,1)
# No new disclosure site: appended diagnostics call the byte-identical existing helper.
body=body.replace('  assert_received_fixture(Bytes.secure_equals(receive_initial_message','  assert_received_fixture(Bytes.secure_equals(receive_initial_message')
appended='\n# Owned scratch diagnostics: original four tests above remain unchanged.\n'+body
for i,(name,_) in enumerate(markers,1):
 appended+=f'\ntest("diagnostic stage {i:02d} {name}") do\n  assert_received_fixture(Result.unwrap_or(diagnostic_stage({i}), false))\nend\n'
p.write_text(original+appended)
assert p.read_text().startswith(original)
assert p.read_text().count('declassify(')==original.count('declassify(')==1
(root/'stages.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),(original+appended).splitlines(True),fromfile='a/tests/header_receive.test.mpl',tofile='b/tests/header_receive.test.mpl')))
pins={str(f.relative_to(source)):hashlib.sha256(f.read_bytes()).hexdigest() for f in source.rglob('*') if f.is_file()}
(root/'base-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
(root/'stage-map.json').write_text(json.dumps([{'stage':i,'name':name,'before':marker} for i,(name,marker) in enumerate(markers,1)],indent=2)+'\n')
profile=(proof/'offline.sb').read_text().replace(str(proof),str(root))
(root/'offline.sb').write_text(profile)
print('Prepared stages; original test is exact prefix, one unchanged existing declassification site.')
