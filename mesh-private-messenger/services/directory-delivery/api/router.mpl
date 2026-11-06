from Api.CreditSignup import handle_credit_signup, handle_credit_signup_policy
from Api.CreditRecovery import handle_credit_recovery
from Api.OhttpHttp import handle_ohttp
from Api.CreditAttachment import handle_credit_attachment_grant
from Api.CreditPostage import (
  handle_credit_postage,
  handle_credit_postage_reconcile,
  handle_postage_policy
)
from Api.CreditHttp import (
  handle_credit_redeem,
  handle_credit_issuer_announce,
  handle_credit_issuer_admit,
  handle_credit_prune,
  handle_credit_issuer_discovery,
  handle_credit_issuer_candidate,
  handle_credit_issuer_cursor,
  handle_credit_retention
)
from Api.AnchorHttp import (
  handle_anchor_candidate,
  handle_anchor_cosigns,
  handle_v1_anchor_receipt,
  handle_v2_anchor_receipt,
  handle_record_anchor_receipt
)
from Api.Http import (
  handle_c2sp_push,
  handle_v2_checkpoint,
  handle_v1_checkpoint_history,
  handle_v2_checkpoint_history,
  handle_v1_leaf_proof,
  handle_v2_leaf_proof,
  handle_v2_consistency,
  handle_v2_inclusion,
  handle_v2_witnesses,
  handle_v2_witness_submit,
  handle_v2_resolve,
  handle_checkpoint_note,
  handle_legacy_bridge
)
from Api.Http import (
  handle_jobs,
  handle_transparency_registry,
  handle_push_witness_registry,
  handle_witness_health,
  handle_witness_job,
  handle_acknowledge,
  handle_delete_account,
  handle_fetch,
  handle_leave_device,
  handle_health,
  handle_prekey_claim,
  handle_prekeys_publish,
  handle_push_bind,
  handle_push_unbind,
  handle_register_device,
  handle_resolve_devices,
  handle_revoke_device,
  handle_sealed_submit,
  handle_submit,
  handle_transparency_checkpoint,
  handle_transparency_consistency,
  handle_transparency_inclusion,
  handle_transparency_witness_submit,
  handle_transparency_witnesses
)

pub fn direct_delivery_compatibility_enabled(value :: String) -> Bool do
  value == "enabled"
end

pub fn build_router() do
  let router = HTTP.router()
    |> HTTP.on_get("/health", handle_health)
    |> HTTP.on_post("/internal/v1/ohttp", handle_ohttp)
    |> HTTP.on_post("/v1/credits/issuer", handle_credit_issuer_discovery)
    |> HTTP.on_post("/v1/credits/retention", handle_credit_retention)
    |> HTTP.on_post("/v1/credits/signup", handle_credit_signup)
    |> HTTP.on_post("/v1/credits/signup-policy", handle_credit_signup_policy)
    |> HTTP.on_post("/v1/credits/reconcile", handle_credit_recovery)
    |> HTTP.on_post("/v1/credits/postage-policy", handle_postage_policy)
    |> HTTP.on_post("/internal/credits/postage", handle_credit_postage)
    |> HTTP.on_post("/internal/credits/postage/reconcile", handle_credit_postage_reconcile)
    |> HTTP.on_post("/internal/credits/redeem", handle_credit_redeem)
    |> HTTP.on_post("/internal/credits/attachments/grant", handle_credit_attachment_grant)
    |> HTTP.on_post("/internal/credits/issuers/announce", handle_credit_issuer_announce)
    |> HTTP.on_post("/internal/credits/issuers/admit", handle_credit_issuer_admit)
    |> HTTP.on_post("/internal/credits/issuers/evidence", handle_credit_issuer_candidate)
    |> HTTP.on_get("/internal/credits/issuers/cursor", handle_credit_issuer_cursor)
    |> HTTP.on_post("/internal/credits/prune", handle_credit_prune)
    |> HTTP.on_get("/v1/transparency/registry", handle_transparency_registry)
    |> HTTP.on_get("/v1/transparency/anchor/:sequence", handle_v1_anchor_receipt)
    |> HTTP.on_get("/v2/transparency/anchor/:sequence", handle_v2_anchor_receipt)
    |> HTTP.on_post("/internal/v1/transparency/anchors", handle_record_anchor_receipt)
    |> HTTP.on_get("/internal/v1/transparency/anchor-candidate/:version", handle_anchor_candidate)
    |> HTTP.on_post("/internal/v1/transparency/anchor-cosigns", handle_anchor_cosigns)
    |> HTTP.on_get("/internal/v1/transparency/push-witnesses", handle_push_witness_registry)
    |> HTTP.on_post("/internal/v2/transparency/c2sp-push", handle_c2sp_push)
    |> HTTP.on_get("/internal/v1/transparency/witness-health", handle_witness_health)
    |> HTTP.on_put("/v1/devices/register", handle_register_device)
    |> HTTP.on_post("/v1/devices/resolve", handle_resolve_devices)
    |> HTTP.on_post("/v1/devices/revoke", handle_revoke_device)
    |> HTTP.on_post("/v1/accounts/delete", handle_delete_account)
    |> HTTP.on_post("/v1/devices/leave", handle_leave_device)
    |> HTTP.on_post("/v1/prekeys/one-time/batch", handle_prekeys_publish)
    |> HTTP.on_post("/v1/prekeys/bundle", handle_prekey_claim)
  let router = if direct_delivery_compatibility_enabled(Env.get("MESSENGER_DIRECT_DELIVERY_COMPATIBILITY",
    "")) do
    HTTP.on_post(router, "/v1/envelopes/batch", handle_submit)
  else
    router
  end
  router
    |> HTTP.on_post("/internal/v1/jobs/directory", handle_jobs)
    |> HTTP.on_post("/internal/v1/jobs/witness", handle_witness_job)
    |> HTTP.on_post("/internal/v1/envelopes/sealed", handle_sealed_submit)
    |> HTTP.on_post("/v1/mailbox/fetch", handle_fetch)
    |> HTTP.on_post("/v1/mailbox/ack", handle_acknowledge)
    |> HTTP.on_put("/v1/push/bind", handle_push_bind)
    |> HTTP.on_post("/v1/push/unbind", handle_push_unbind)
    |> HTTP.on_get("/v1/transparency/checkpoint.note", handle_checkpoint_note)
    |> HTTP.on_get("/v2/transparency/checkpoint.note", handle_checkpoint_note)
    |> HTTP.on_get("/v2/transparency/checkpoint", handle_v2_checkpoint)
    |> HTTP.on_post("/v2/transparency/checkpoint", handle_v2_checkpoint_history)
    |> HTTP.on_post("/v2/transparency/leaf", handle_v2_leaf_proof)
    |> HTTP.on_get("/v2/transparency/consistency", handle_v2_consistency)
    |> HTTP.on_post("/v2/transparency/consistency", handle_v2_consistency)
    |> HTTP.on_get("/v2/transparency/inclusion", handle_v2_inclusion)
    |> HTTP.on_post("/v2/transparency/inclusion", handle_v2_inclusion)
    |> HTTP.on_get("/v2/transparency/witnesses", handle_v2_witnesses)
    |> HTTP.on_post("/v2/transparency/witnesses", handle_v2_witness_submit)
    |> HTTP.on_post("/v2/transparency/legacy-bridge", handle_legacy_bridge)
    |> HTTP.on_post("/v2/devices/resolve", handle_v2_resolve)
    |> HTTP.on_get("/v1/transparency/checkpoint", handle_transparency_checkpoint)
    |> HTTP.on_post("/v1/transparency/checkpoint", handle_v1_checkpoint_history)
    |> HTTP.on_post("/v1/transparency/leaf", handle_v1_leaf_proof)
    |> HTTP.on_get("/v1/transparency/inclusion", handle_transparency_inclusion)
    |> HTTP.on_post("/v1/transparency/inclusion", handle_transparency_inclusion)
    |> HTTP.on_get("/v1/transparency/consistency", handle_transparency_consistency)
    |> HTTP.on_post("/v1/transparency/consistency", handle_transparency_consistency)
    |> HTTP.on_get("/v1/transparency/witnesses", handle_transparency_witnesses)
    |> HTTP.on_post("/v1/transparency/witnesses", handle_transparency_witness_submit)
end
