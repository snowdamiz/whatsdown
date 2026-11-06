from Transparency.Config import SecurityConfig, decode_security_config, valid_witness_id
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Transparency.AttendanceRead import AttendanceState, read_attendance, attendance_report

pub struct AttendanceQuery do
  log_name :: String
  epoch :: U64
end

pub fn parse_attendance_command(args :: List<String>) -> AttendanceQuery!String do
  let usage = "usage: morse attendance --log LOG_NAME --epoch EPOCH"
  if List.length(args) != 6
    || List.get(args, 1) != "attendance"
    || List.get(args, 2) != "--log"
    || List.get(args, 4) != "--epoch"
    || !valid_witness_id(List.get(args, 3))
    || String.length(List.get(args, 3)) > 32 do
    return Err(usage)
  end
  let epoch = case U64.parse(List.get(args, 5)) do
    Err(_) -> return Err(usage)
    Ok(value) -> value
  end
  if U64.to_string(epoch) != List.get(args, 5) do
    return Err(usage)
  end
  Ok(AttendanceQuery { log_name: List.get(args, 3), epoch: epoch })
end

pub fn run_attendance_command(args :: List<String>) -> Int!String do
  let query = parse_attendance_command(args)?
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Err("MESSENGER_SECURITY_CONFIG is required for attendance")
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  let pins = case configured_anchor_pins(config)? do
    None -> return Err("attendance_requires_anchor_pins")
    Some(value) -> value
  end
  if pins.log_name != query.log_name do
    return Err("attendance_log_mismatch")
  end
  let minimum = Env.get("MORSE_ATTENDANCE_MIN_CONTEXT_SLOT", "0")
  let slot = U64.parse(minimum)?
  if U64.to_string(slot) != minimum do
    return Err("invalid_attendance_minimum_slot")
  end
  let result = read_attendance(pins,
    config.service_public_key,
    config.log_version,
    query.epoch,
    slot)?
  println(attendance_report(result))
  Ok(0)
end
