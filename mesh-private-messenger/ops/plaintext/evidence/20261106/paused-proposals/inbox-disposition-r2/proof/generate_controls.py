from prooflib import *

MOBILE = SNAP / 'mesh-private-messenger/packages/mobile-core'
manifest = '[package]\nname="inbox-baseline-proof"\nversion="0.1.0"\n[dependencies]\nmobile={path="' + str(MOBILE) + '"}\n'
cases = []

def write_case(name, text, positive, pair=None, expected=None, artifact='executable'):
    directory = ROOT / 'controls' / name
    directory.mkdir(parents=True, exist_ok=False)
    (directory/'mesh.toml').write_text(manifest)
    (directory/'main.mpl').write_text(text+'\nfn main() do nil end\n')
    cases.append({'name':name, 'positive':positive, 'matched_positive':pair, 'artifact':artifact,
        'expected_e0093':expected or [], 'source_sha256':sha(directory/'main.mpl'),
        'never_execute':True})

def expectations(text, subject='Http.body_bytes'):
    return [{'file':'main.mpl','line':i, 'subject':subject} for i,line in enumerate(text.splitlines(),1) if subject+'(' in line]

for private in (False, True):
    tag = 'private' if private else 'public'
    st = 'Plaintext<String>' if private else 'String'
    bt = 'Plaintext<Bool>' if private else 'Bool'
    source = 'from Mobile.Inbox import permanent_direct_delivery_error, header_selection_unfinished\n\n'
    for label, classifier in [('permanent','permanent_direct_delivery_error'),('unfinished','header_selection_unfinished')]:
        source += f'''fn {label}_bool_body(error :: {st}) -> Int do
  let verdict :: Bool = {classifier}(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn {label}_branch_constant(error :: {st}) -> Int do
  let verdict :: Bool = {classifier}(error)
  if verdict do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end

fn {label}_selected_error(flag :: {bt}) -> Int do
  let error = if flag do "wrong_mailbox" else "unknown_future_error" end
  let verdict :: Bool = {classifier}(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

'''
        for suffix, value in [('known_permanent','view_once_reference_refused'),('known_header','header_selection_pending'),('unknown','unknown_future_error')]:
            source += f'''fn {label}_{suffix}() -> Int do
  let error :: {st} = "{value}"
  let verdict :: Bool = {classifier}(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

'''
    source += f'''fn explicit_bool_body(flag :: {bt}) -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(flag)))
end

fn explicit_bool_branch_constant(flag :: {bt}) -> Int do
  if flag do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end
'''
    write_case('classifiers-'+tag, source, not private, 'classifiers-public' if private else None, expectations(source) if private else [])

batch_imports = 'from Mobile.Inbox import process_delivery_batch\nfrom Mobile.Types import MobileBatchRequest\n\n'
for private in (False, True):
    tag = 'private' if private else 'public'
    bt = 'Plaintext<Bool>' if private else 'Bool'
    rt = 'Plaintext<MobileBatchRequest>' if private else 'MobileBatchRequest'
    yt = 'Plaintext<Bytes>' if private else 'Bytes'
    body = f'''fn batch_caller_pc(flag :: {bt}, request :: MobileBatchRequest) -> Bytes!String do
  if flag do
    process_delivery_batch(request)
  else
    Ok(Bytes.empty())
  end
end

fn batch_selected(flag :: {bt}, first :: MobileBatchRequest, second :: MobileBatchRequest) -> Bytes!String do
  let selected = if flag do first else second end
  process_delivery_batch(selected)
end

fn batch_path_selected(flag :: {bt}, first_path :: String, second_path :: String, batch :: Bytes) -> Bytes!String do
  let path = if flag do first_path else second_path end
  process_delivery_batch(MobileBatchRequest {{ database_path: path, batch: batch }})
end

fn batch_whole_argument(request :: {rt}) -> Bytes!String do
  process_delivery_batch(request)
end

fn batch_wire_argument(batch :: {yt}, path :: String) -> Bytes!String do
  process_delivery_batch(MobileBatchRequest {{ database_path: path, batch: batch }})
end
'''
    source = batch_imports + body
    write_case('batch-effects-'+tag, source, not private, 'batch-effects-public' if private else None,
        expectations(source,'process_delivery_batch') if private else [])
    # Native export signatures stay Bytes -> Result<Bytes,String>. Explicit labels
    # are introduced in generated wrappers, never in any application export.
    source = batch_imports
    native_cases = [
        ('caller_pc', f'''  let flag :: {bt} = Bytes.length(input) > 0
  if flag do
    process_delivery_batch(MobileBatchRequest {{ database_path: "/never-open/proof-a.db", batch: input }})
  else
    Ok(Bytes.empty())
  end'''),
        ('batch_selection', f'''  let flag :: {bt} = Bytes.length(input) > 0
  let first = MobileBatchRequest {{ database_path: "/never-open/proof-a.db", batch: input }}
  let second = MobileBatchRequest {{ database_path: "/never-open/proof-b.db", batch: input }}
  let selected = if flag do first else second end
  process_delivery_batch(selected)'''),
        ('path_selection', f'''  let flag :: {bt} = Bytes.length(input) > 0
  let path = if flag do "/never-open/proof-a.db" else "/never-open/proof-b.db" end
  process_delivery_batch(MobileBatchRequest {{ database_path: path, batch: input }})'''),
        ('whole_argument', f'''  let request :: {rt} = MobileBatchRequest {{ database_path: "/never-open/proof-a.db", batch: input }}
  process_delivery_batch(request)'''),
        ('wire_argument', f'''  let batch :: {yt} = input
  process_delivery_batch(MobileBatchRequest {{ database_path: "/never-open/proof-a.db", batch: batch }})'''),
    ]
    exports = []
    for name, code in native_cases:
        line = len(source.splitlines())+1
        fn = 'proof_'+name
        source += f'@export("{fn}") pub fn {fn}(input :: Bytes) -> Bytes!String do\n{code}\nend\n\n'
        exports.append({'file':'main.mpl','line':line,'subject':fn})
    write_case('batch-native-'+tag, source, not private, 'batch-native-public' if private else None,
        (expectations(source,'process_delivery_batch')+exports) if private else [], 'staticlib')

save('control-plan.json', cases)
profile = f'''(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{ROOT}"))
(allow file-write* (literal "/dev/null"))
(allow file-write* (regex #"^/private/tmp/mesh_mobile_(inbox-poison-(alice|bob)|groups-(alice|linked|bob))_[0-9a-f]{{16}}[.]db(-wal|-shm|-journal)?$"))
(deny file-read* (subpath "/Users/andreyyurlov/Library/Keychains"))
'''
(ROOT/'offline.sb').write_text(profile)
print(json.dumps({'controls':len(cases),'expected_classifier_http_sites':len(cases[1]['expected_e0093'])}))
