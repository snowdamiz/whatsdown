from Api.Http import handle_acknowledge, handle_fetch, handle_health, handle_register, handle_resolve, handle_submit

pub fn build_router() do
  HTTP.router()
    |> HTTP.on_get("/health", handle_health)
    |> HTTP.on_put("/v1/directory/register", handle_register)
    |> HTTP.on_get("/v1/directory/resolve", handle_resolve)
    |> HTTP.on_post("/v1/directory/resolve", handle_resolve)
    |> HTTP.on_post("/v1/envelopes/batch", handle_submit)
    |> HTTP.on_post("/v1/mailbox/fetch", handle_fetch)
    |> HTTP.on_post("/v1/mailbox/ack", handle_acknowledge)
end
