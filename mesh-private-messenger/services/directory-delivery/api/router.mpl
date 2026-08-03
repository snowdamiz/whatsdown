from Api.Http import handle_acknowledge, handle_fetch, handle_health, handle_register, handle_register_device, handle_resolve, handle_resolve_devices, handle_revoke_device, handle_sealed_submit, handle_submit, handle_transparency_checkpoint, handle_transparency_consistency, handle_transparency_inclusion, handle_transparency_witness_submit, handle_transparency_witnesses

pub fn build_router() do
  HTTP.router()
    |> HTTP.on_get("/health", handle_health)
    |> HTTP.on_put("/v1/directory/register", handle_register)
    |> HTTP.on_get("/v1/directory/resolve", handle_resolve)
    |> HTTP.on_post("/v1/directory/resolve", handle_resolve)
    |> HTTP.on_put("/v1/devices/register", handle_register_device)
    |> HTTP.on_post("/v1/devices/resolve", handle_resolve_devices)
    |> HTTP.on_post("/v1/devices/revoke", handle_revoke_device)
    |> HTTP.on_post("/v1/envelopes/batch", handle_submit)
    |> HTTP.on_post("/internal/v1/envelopes/sealed", handle_sealed_submit)
    |> HTTP.on_post("/v1/mailbox/fetch", handle_fetch)
    |> HTTP.on_post("/v1/mailbox/ack", handle_acknowledge)
    |> HTTP.on_get("/v1/transparency/checkpoint", handle_transparency_checkpoint)
    |> HTTP.on_get("/v1/transparency/inclusion", handle_transparency_inclusion)
    |> HTTP.on_post("/v1/transparency/inclusion", handle_transparency_inclusion)
    |> HTTP.on_get("/v1/transparency/consistency", handle_transparency_consistency)
    |> HTTP.on_post("/v1/transparency/consistency", handle_transparency_consistency)
    |> HTTP.on_get("/v1/transparency/witnesses", handle_transparency_witnesses)
    |> HTTP.on_post("/v1/transparency/witnesses", handle_transparency_witness_submit)
end
