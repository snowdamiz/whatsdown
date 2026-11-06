from Read import read_public_report
from SnapshotHttp import serve_snapshot

fn run() -> String!String do
  let args = Env.args()
  if List.length(args) == 2 && List.get(args, 1) == "--serve" do
    return serve_snapshot()
  end
  if List.length(args) != 3 || List.get(args, 1) != "--input" do
    Err("usage: public-chain-report --input EXPLICIT_READ_CONFIG")
  else
    read_public_report(File.read(List.get(args, 2))?)
  end
end

fn main() do
  case run() do
    Err(error) -> do
      IO.eprintln(error)
      Process.exit(1)
    end
    Ok(value) -> println(value)
  end
end
