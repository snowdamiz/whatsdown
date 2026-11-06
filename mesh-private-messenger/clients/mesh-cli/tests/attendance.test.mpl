from Client.Attendance import AttendanceQuery, parse_attendance_command

test("attendance requires an explicit log and canonical unsigned epoch without defaults") do
  for epoch in ["0", "11", "9007199254740993", "18446744073709551615"] do
    case parse_attendance_command([
      "morse",
      "attendance",
      "--log",
      "morse-main",
      "--epoch",
      epoch
    ]) do
      Err(_) -> assert(false)
      Ok(value) -> do
        assert(value.log_name == "morse-main")
        assert(U64.to_string(value.epoch) == epoch)
      end
    end
  end
  for args in [
    ["morse", "attendance"],
    ["morse", "attendance", "--log", "morse-main"],
    ["morse", "attendance", "--log", "Morse-main", "--epoch", "11"],
    ["morse", "attendance", "--log", String.repeat("a", 33), "--epoch", "11"],
    ["morse", "attendance", "--epoch", "11", "--log", "morse-main"],
    ["morse", "bonds", "--log", "morse-main", "--epoch", "11"],
    ["morse", "attendance", "--log", "morse-main", "--epoch", "11", "extra"]
  ] do
    case parse_attendance_command(args) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for epoch in ["", "01", "-1", "+1", "1.0", " 1", "18446744073709551616"] do
    case parse_attendance_command([
      "morse",
      "attendance",
      "--log",
      "morse-main",
      "--epoch",
      epoch
    ]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
end
