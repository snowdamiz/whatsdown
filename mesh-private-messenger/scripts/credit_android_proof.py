"""Owned Android credit proof using production JNI and packaged trust roots."""
from attachment_android_proof import AttachmentAndroidProof


class CreditAndroidProof(AttachmentAndroidProof):
    bundle = 'app.morse.credit.proof.android'
    instrumentation_class = 'CreditProofTest'

    def __init__(self, product, work, security_config, issuer_tls_root=None, *, artifact_dir=None):
        issuer = security_config.splitlines()[9]
        network = '\n'.join(['2', '1', issuer, issuer, issuer,
            issuer.replace('https://', 'wss://')+'/v1/mailbox/stream', '1'])
        super().__init__(product, work, security_config,
            proof_source=product/'apps/mobile/modules/mesh-messenger/android/credit-proof/CreditProof.kt',
            network_config=network, credit_purpose='test', lightning_network='regtest',
            issuer_tls_root=issuer_tls_root, artifact_dir=artifact_dir)
