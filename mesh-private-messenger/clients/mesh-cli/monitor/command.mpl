from Transparency.Config import valid_witness_id

pub struct MonitorCommand do
  log_name :: String
  once :: Bool
  port :: Int
end

fn usage() -> String do
  "usage: mesh-cli monitor --log NAME [--once] [--port 1..65535]"
end

fn options(args :: List<String>,
  index :: Int,
  value :: MonitorCommand,
  port_set :: Bool) -> MonitorCommand!String do
  if index == List.length(args) do
    if value.log_name == "" do
      Err(usage())
    else
      Ok(value)
    end
  else
    let option = List.get(args, index)
    if option == "--once" && !value.once do
      options(args, index + 1, %{value | once: true}, port_set)
    else if option == "--log" && value.log_name == "" && index + 1 < List.length(args) do
      let name = List.get(args, index + 1)
      if !valid_witness_id(name) || String.length(name) > 32 do
        Err(usage())
      else
        options(args, index + 2, %{value | log_name: name}, port_set)
      end
    else if option == "--port" && !port_set && index + 1 < List.length(args) do
      let text = List.get(args, index + 1)
      let port = case String.to_int(text) do
        None -> return Err(usage())
        Some(value) -> value
      end
      if port < 1 || port > 65535 || Int.to_string(port) != text do
        Err(usage())
      else
        options(args, index + 2, %{value | port: port}, true)
      end
    else
      Err(usage())
    end
  end
end

pub fn parse_monitor_command(args :: List<String>) -> MonitorCommand!String do
  if List.length(args) < 4 || List.length(args) > 7 || List.get(args, 1) != "monitor" do
    Err(usage())
  else
    options(args, 2, MonitorCommand { log_name: "", once: false, port: 18100 }, false)
  end
end
