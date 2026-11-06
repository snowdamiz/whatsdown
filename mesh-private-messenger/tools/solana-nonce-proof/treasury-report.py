#!/usr/bin/env python3
"""Checkpoint after prove-credit-treasury.sh's complete successful gate sequence."""
import datetime
import hashlib
import json
import os
from pathlib import Path
PRODUCT=Path(__file__).resolve().parents[2]
PUBLIC=Path(os.environ.get("MESH_LANG_ROOT",PRODUCT/"../mesh-lang")).resolve()
PROOF=Path(os.environ.get("MORSE_PROOF_DIR",PRODUCT.parent/".morse/witness-proof"))
paths=[]
for folder in ["storage","payment","runtime"]:
    paths.extend((PRODUCT/"services/credit-issuer"/folder).glob("treasury*.mpl"))
paths.extend(PRODUCT/"services/credit-issuer"/p for p in ["storage/issuance.mpl","payment/verify.mpl","payment/observation.mpl","tests/treasury.test.mpl","tests/issuance.test.mpl","migrations/003_treasury.sql","migrations/004_treasury_batches.sql","tests/treasury_batch.test.mpl","TREASURY.md"])
paths.extend((PRODUCT/"services/credit-issuer/tests").glob("treasury*.test.mpl"))
paths.extend((PRODUCT/"services/credit-issuer/migrations").glob("*.sql"))
paths.extend((PRODUCT/"services/credit-issuer/tests").glob("treasury*.mjs"))
paths.extend([PRODUCT/"services/credit-issuer/main.mpl",PRODUCT/"services/credit-issuer/runtime/config.mpl",PRODUCT/"ops/credit-treasury/OPERATIONS.md"])
paths.extend((PRODUCT/"tools/solana-nonce-proof").glob("*.mjs"))
paths.extend((PRODUCT/"tools/solana-nonce-proof/fixtures").glob("*.fixture"))
paths.extend([PRODUCT/"tools/solana-nonce-proof/Cargo.lock",PRODUCT/"tools/solana-nonce-proof/src/main.rs",PRODUCT/"programs/morse-rewards/examples/treasury_payment_fixture.rs",PRODUCT/"scripts/prove-credit-treasury.sh",PRODUCT/"scripts/prove-credit-treasury.py",PRODUCT/"ops/credit-treasury/DESIGN.md"])
paths.extend(PUBLIC/"packages/mesh-solana"/p for p in ["solana/read.mpl","solana/nonce.mpl","solana/transaction_read.mpl","solana/transaction_write.mpl","TRANSACTION_READ.md","NONCE.md"])
paths.append(PUBLIC/"compiler/meshc/tests/e2e_solana_rpc_redirect.rs")
checks={"public_solana_package":True,"public_rpc_redirect_opt0_opt2":True,"owned_postgresql_accounting":True,"integer_split":True}
reports={}
for name,file in {"nonce_bank":"solana-nonce-bank.json","sol_refund":"credits-treasury-rpc.json","usdc_refund":"credits-treasury-usdc.json","rewards_funding":"credits-treasury-funding-sbf.json","batch_sol":"credits-treasury-batch-sol.json","batch_usdc":"credits-treasury-batch-usdc.json","batch_atomic_failure":"credits-treasury-batch-failure.json","production_service":"credits-treasury-service.json"}.items():
    reports[name]=json.loads((PROOF/file).read_text())
    if reports[name].get("passed") is not True:
        raise SystemExit(f"Unpassed gate {name}")
    checks[name]=True
result={"schema_version":1,"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"passed":True,"checks":checks,"reports":reports,"fixture_boundaries":["Local loopback views share one disposable bank; no claim of independent provider operators","Weekly rewards SBF proof starts from a frozen accounting fixture; owned SQL tests qualify snapshot membership separately","No live funds or production deployment/activation; local service proof runs the explicitly enabled empty worker","Production service probe proves explicit provisioning, disabled purchases, restart and empty worker; funded movement execution is separately qualified through production Runtime APIs","SOL witness amounts remain explicit conversion-pending; no swap implemented"],"compiler_sha256":hashlib.sha256(Path(os.environ.get("MESHC",PUBLIC/"target/debug/meshc")).read_bytes()).hexdigest(),"isolated_oracle_audit_clean":False,"oracle_production_dependency":False,"sources":[{"path":str(path.resolve()),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(set(paths))]}
PROOF.mkdir(parents=True,exist_ok=True)
(PROOF/"credits-treasury-local.json").write_text(json.dumps(result,indent=2)+"\n")
