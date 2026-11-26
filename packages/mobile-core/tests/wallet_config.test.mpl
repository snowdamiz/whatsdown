from MobileCore import wallet_rpc_urls_export
from Tests.AnchorSupport import install_anchor_config, rpc_urls
from Tests.Support import append, repeated, vector

fn joined(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    joined(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

# u8 1 || u8 count || count x vector32(url)

fn expected(urls :: List<String>) -> Bytes!String do
  let rows = for url in urls do
    vector(Bytes.from_utf8(url))?
  end
  joined(rows, 0, append(repeated(1, 1)?, repeated(List.length(urls), 1)?)?)
end

fn listed(anchored :: Bool, urls :: List<String>) -> Bool!String do
  assert(install_anchor_config(anchored)?)
  Ok(wallet_rpc_urls_export(Bytes.empty())? == expected(urls)?)
end

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

test("the wallet reads exactly the RPC URLs the build pins, in order") do
  assert(run("anchored", listed(true, rpc_urls())))
end

test("a build that pins no anchor gives the wallet no RPC to use") do
  assert(run("unanchored", listed(false, List.new())))
end

test("the wallet config export takes no request bytes") do
  assert(run("config", install_anchor_config(true)))
  assert(wallet_rpc_urls_export(Bytes.from_utf8("x")) == Err("invalid_request"))
end
