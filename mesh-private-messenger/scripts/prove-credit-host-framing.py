#!/usr/bin/env python3
"""Run identical hostile credit request vectors through the actual host decoders."""
from pathlib import Path
import os
import subprocess
import tempfile

PRODUCT = Path(__file__).resolve().parents[1]
MODULE = PRODUCT/'apps/mobile/modules/mesh-messenger'


def main():
    def packet(*fields):
        return len(fields).to_bytes(4, 'big') + b''.join(len(field).to_bytes(4, 'big')+field for field in fields)
    database = b'/app/Documents/morse.db'
    alternate = b'/app/Documents/other.db'
    vectors = []
    def add(name, body, accepted, path=database):
        vectors.append((f'mesh_messenger_credit_{name}', path, body, accepted))
    for name, fields in [('balance', []), ('recover', [b'x'*32]), ('prepare', [b'\0\0\0d', b'\2']),
        ('quote', [b'x'*32, b'q'*1024]), ('finalize', [b'x'*32, b'r'*512070]),
        ('receipt', [b'r'*462]), ('postage_prepare', [b'a', b'b', b'c']),
        ('attachment_prepare', [b'a', b'b', b'c', b'd']), ('attachment_part', [b'a', b'b', b'p'*65536])]:
        add(name, packet(database,*fields), True)
        add(name, packet(alternate,*fields), False)
    for name, fields in [('discover_online', []), ('purchase_continue', [b'x'*32]),
        ('action_continue', [b'x'*32, b'\0']), ('signup_policy_online', [])]:
        body = packet(database,*fields)
        add(name, body, True)
        add(name, packet(alternate,*fields), False)
        add(name, body+b'\0', False)
        add(name, packet(database,*fields,b'unknown'), False)
    for name, fields in [('credit_attachment_grant',[b'x'*32]), ('credit_attachment_upload',[b'x'*32,b'\0'*4]),
        ('credit_attachment_complete',[b'x'*32]), ('credit_attachment_delete',[b'x'*32]),
        ('attachment_fetch_chunk',[b'reference',b'\0'*4]), ('credit_postage_continue',[b'x'*32]), ('postage_policy_view',[b'a'*32]),
        ('postage_policy_prepare',[b'\5']), ('postage_policy_publish',[b'\0'*7+b'\2',b'\0'*7+b'\1',b'\5'])]:
        for path, body, accepted in [(database,packet(database,*fields),True),
            (database,packet(alternate,*fields),False), (database,packet(database,*fields)+b'\0',False),
            (database,packet(database,*fields,b'unknown'),False)]:
            vectors.append(('mesh_messenger_'+name,path,body,accepted))
    for name, fields in [('attachment_upload', [b'file.bin', b'application/octet-stream', b'x']),
                         ('attachment_discard', [b'opaque-ticket'])]:
        for body, accepted in [(packet(database,*fields),True), (packet(alternate,*fields),False),
                               (packet(database,*fields)+b'\0',False), (packet(database,*fields,b'extra'),False)]:
            vectors.append(('mesh_messenger_'+name,database,body,accepted))
    for size, accepted in [(16777216,True),(16777217,False)]:
        vectors.append(('mesh_messenger_attachment_upload',database,packet(database,b'file.bin',b'application/octet-stream',b'x'*size),accepted))
    def ordinary(*fields):
        return b''.join(len(field).to_bytes(4,'big')+field for field in fields)
    for body, accepted in [(ordinary(database,b'alice'),True), (ordinary(alternate,b'alice'),False),
                           (ordinary(database,b'a'*65),True), (ordinary(database,b'a'*66),False),
                           (ordinary(database,b'alice')+b'\0',False), (packet(database,b'alice'),False),
                           (ordinary(database,b''),False)]:
        vectors.append(('mesh_messenger_directory_resolve',database,body,accepted))
    for body, accepted in [(ordinary(database,b'\0'),True), (ordinary(database,b'\1'),True),
                           (ordinary(alternate,b'\0'),False), (ordinary(database,b''),False),
                           (ordinary(database,b'\0\0'),False), (ordinary(database,b'\0')+b'\0',False),
                           (packet(database,b'\0'),False)]:
        vectors.append(('mesh_messenger_outbox_drain',database,body,accepted))
    for name, fields in [('push_flow_intent', [b'\0']),
                         ('push_flow_complete', [b't'*50, b'\0']),
                         ('push_flow_send', [b't'*50])]:
        for body, accepted in [(ordinary(database,*fields),True),
                               (ordinary(alternate,*fields),False),
                               (ordinary(database,*fields)+b'\0',False),
                               (packet(database,*fields),False),
                               (ordinary(database,*fields,b'extra'),False),
                               (ordinary(database,b'',*fields[1:]),False),
                               (ordinary(database,fields[0]+b'x',*fields[1:]),False)]:
            vectors.append(('mesh_messenger_'+name,database,body,accepted))
    for name, maxima in [('push_flow_begin',[36134,1]), ('account_delete',[36134]),
                         ('account_discard',[36134]), ('account_capabilities',[36134]),
                         ('devices_renew',[305260]), ('device_revoke',[305260,16]),
                         ('journal_load_bound',[36134,256]), ('journal_save_bound',[36134,256,262144])]:
        fields=[b'x'*limit for limit in maxima]
        cases=[(ordinary(database,*fields),True),(ordinary(alternate,*fields),False),
               (ordinary(database,*fields)+b'\0',False),(packet(database,*fields),False)]
        for index in range(len(fields)):
            empty=fields.copy();empty[index]=b''
            over=fields.copy();over[index]+=b'x'
            cases.extend([(ordinary(database,*empty),False),(ordinary(database,*over),False)])
        for body,accepted in cases:
            vectors.append(('mesh_messenger_'+name,database,body,accepted))
    fanout = [database,b'p'*36134,b'bob',b'\1',b'hello',b'',b'']
    def fanout_case(fields,accepted,path=database):
        vectors.append(('mesh_messenger_fanout_send',path,ordinary(*fields),accepted))
    fanout_case(fanout,True)
    fanout_case([*fanout[:4],b'',b'',b'attachment'],True)
    fanout_case([alternate,*fanout[1:]],False)
    vectors.extend([('mesh_messenger_fanout_send',database,ordinary(*fanout)+b'\0',False),
                    ('mesh_messenger_fanout_send',database,packet(*fanout),False),
                    ('mesh_messenger_fanout_send',database,ordinary(*fanout,b'extra'),False),
                    ('mesh_messenger_fanout_send',database,ordinary(*fanout)[:-1],False)])
    bounds=[4096,36134,65,1,32000,32,16384]
    for index,maximum in enumerate(bounds):
        over=fanout.copy();over[index]=b'x'*(maximum+1)
        fanout_case(over,False)
        if index<4:
            empty=fanout.copy();empty[index]=b''
            fanout_case(empty,False)
    maximum=[b'x'*limit for limit in bounds]
    assert len(ordinary(*maximum))==88740
    fanout_case(maximum,True,path=maximum[0])
    for body in [b'', b'\0'*4, b'\xff'*8, packet(database)[:-1], packet(database)+b'\0',
        packet(database,b'x')[:-1], packet(database)+b'\0'*4,
        packet(database,b'x'*1050001), packet(database,b'a',b'b',b'c'),
        b'\0\0\0\1\xff\xff\xff\xff'+database]:
        add('balance', body, False)
    add('balance', packet(database), False, b'')
    add('balance', packet(database.replace(b'morse.db',b'./morse.db')), False)
    with tempfile.TemporaryDirectory(prefix='morse-credit-host-') as raw:
        work = Path(raw)
        vector_file = work/'vectors.tsv'
        vector_file.write_text('\n'.join('\t'.join([name,path.hex(),body.hex(),'1' if accepted else '0']) for name,path,body,accepted in vectors)+'\n')
        def run(*args):
            return subprocess.run(list(map(str,args)), check=True)
        run('xcrun','swiftc',MODULE/'ios/MeshMessengerCreditRequest.swift',MODULE/'ios/credit-proof/RequestProof.swift','-o',work/'swift-proof')
        swift = subprocess.run([str(work/'swift-proof'),str(vector_file)])
        cache = Path(os.environ.get('GRADLE_USER_HOME',Path.home()/'.gradle'))/'caches/modules-2/files-2.1'
        def jar(group,name,version):
            found = list((cache/group/name/version).glob('*/*.jar'))
            if len(found) != 1: raise RuntimeError(f'Expected one cached {name}:{version}; run the Android build first')
            return found[0]
        stdlib = jar('org.jetbrains.kotlin','kotlin-stdlib','2.2.0')
        jars = [jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.2.0'),stdlib,
            jar('org.jetbrains.kotlin','kotlin-script-runtime','2.2.0'),
            jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),
            jar('org.jetbrains.kotlin','kotlin-daemon-embeddable','2.2.0'),
            jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.0'),
            jar('org.jetbrains','annotations','13.0')]
        java = Path(os.environ.get('JAVA_HOME','/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home'))/'bin/java'
        run(java,'-cp',os.pathsep.join(map(str,jars)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
            '-no-stdlib','-no-reflect','-classpath',os.pathsep.join(map(str,[stdlib,jars[-1]])),
            MODULE/'android/src/main/java/expo/modules/meshmessenger/MeshMessengerCreditRequest.kt',
            MODULE/'android/credit-proof/RequestProof.kt','-d',work/'proof.jar')
        kotlin = subprocess.run([str(java),'-cp',os.pathsep.join(map(str,[work/'proof.jar',stdlib])),
            'expo.modules.meshmessenger.RequestProofKt',str(vector_file)])
        if swift.returncode or kotlin.returncode: raise SystemExit('Host framing regression failed')
        print(f'{len(vectors)} shared vectors passed on both host implementations')


if __name__ == '__main__':
    main()
