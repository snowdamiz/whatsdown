#!/usr/bin/env python3
"""Compose the owned issuer/TLS proof with the real RN OS handoff.

The original HTTPS proof runs unchanged and retains its evidence. This driver
adds a separate receiver proof after each selected native HTTPS platform. No
screenshots, UI snapshots, recording, live funds or third-party wallet needed.
"""
from pathlib import Path
import importlib.util
import json
import os
import sys
import shutil
import tomllib
import hashlib
from credit_handoff_proof import prove_os_handoff


def main():
    product=Path(__file__).resolve().parents[1]
    output=Path(os.environ.get('MORSE_LIGHTNING_PROOF_DIR',product.parent/'.morse/witness-proof/credit-os-handoff'))
    output.mkdir(parents=True,exist_ok=True)
    os.environ['MORSE_LIGHTNING_PROOF_DIR']=str(output)
    spec=importlib.util.spec_from_file_location('owned_credit_lightning',product/'scripts/prove-credit-lightning.py')
    fixture=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    # Pin the complete app protocol tree before either compiler invocation.
    # Public runtime/compiler pins are supplied by the normal fixture env.
    snapshot=output/'product-snapshot'
    (snapshot/'packages').mkdir(parents=True)
    original_protocol=product/'packages/messenger-protocol'
    copied=snapshot/'packages/messenger-protocol'
    shutil.copytree(original_protocol,copied,ignore=shutil.ignore_patterns('target','.mesh'))
    manifest=(copied/'mesh.toml').read_text()
    for dependency in tomllib.loads(manifest).get('dependencies',{}).values():
        if isinstance(dependency,dict) and 'path' in dependency:
            before=dependency['path']
            manifest=manifest.replace('"'+before+'"','"'+str((original_protocol/before).resolve())+'"')
    (copied/'mesh.toml').write_text(manifest)
    (snapshot/'apps').symlink_to(product/'apps',target_is_directory=True)
    fixture.PRODUCT=snapshot
    source_hashes={str(path.relative_to(copied)):hashlib.sha256(path.read_bytes()).hexdigest() for path in copied.rglob('*') if path.is_file()}
    (output/'protocol-snapshot.json').write_text(json.dumps(source_hashes,indent=2)+'\n')
    original=fixture.prove_native_tls
    results={}
    def combined(product,work,seed,lnd,issuer_origin,set_mode,platform='ios',artifact_dir=None):
        # Keep the existing actual-payment and TLS qualification truthful and
        # unchanged; handoff uses its own unpaid invoice and native app ID.
        evidence=original(product,work,seed,lnd,issuer_origin,set_mode,platform,artifact_dir)
        set_mode(True)
        results[platform]=prove_os_handoff(Path(__file__).resolve().parents[1],output/('os-'+platform),seed,lnd,issuer_origin,set_mode,platform)
        return evidence
    fixture.prove_native_tls=combined
    fixture.main()
    assert results,'select at least one MORSE_LIGHTNING_{IOS,ANDROID}_TLS_PROOF=1'
    (output/'os-handoff.json').write_text(json.dumps({'passed':True,'platforms':results,'screen_capture':False,'live_funds':False},indent=2)+'\n')


if __name__=='__main__': main()
