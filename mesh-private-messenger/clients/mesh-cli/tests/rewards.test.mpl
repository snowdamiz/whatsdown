from Client.Rewards import RewardsQuery, parse_rewards_command
from Solana.Read import pubkey_string

test("rewards reads require explicit canonical program mint log and unsigned epoch pins") do
  let program = "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb"
  let mint = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  let prefix = [
    "morse",
    "rewards",
    "--program",
    program,
    "--mint",
    mint,
    "--log",
    "morse-main",
    "--epoch"
  ]
  for epoch in ["0", "11", "9007199254740993", "18446744073709551615"] do
    case parse_rewards_command(List.append(prefix, epoch)) do
      Err(_) -> assert(false)
      Ok(value) -> do
        assert(pubkey_string(value.program) == program && pubkey_string(value.mint) == mint)
        assert(value.log_name == "morse-main" && U64.to_string(value.epoch) == epoch)
      end
    end
  end
  for args in [
    ["morse", "rewards"],
    ["morse", "rewards", "--program", program, "--mint", mint, "--log", "morse-main"],
    [
      "morse",
      "rewards",
      "--mint",
      mint,
      "--program",
      program,
      "--log",
      "morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      "bad",
      "--mint",
      mint,
      "--log",
      "morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      program,
      "--mint",
      "bad",
      "--log",
      "morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      "11111111111111111111111111111111",
      "--mint",
      mint,
      "--log",
      "morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      program,
      "--mint",
      "11111111111111111111111111111111",
      "--log",
      "morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      program,
      "--mint",
      mint,
      "--log",
      "Morse-main",
      "--epoch",
      "11"
    ],
    [
      "morse",
      "rewards",
      "--program",
      program,
      "--mint",
      mint,
      "--log",
      String.repeat("a", 33),
      "--epoch",
      "11"
    ],
    List.append(List.append(prefix, "11"), "extra")
  ] do
    case parse_rewards_command(args) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for epoch in ["", "01", "-1", "+1", "1.0", " 1", "18446744073709551616"] do
    case parse_rewards_command(List.append(prefix, epoch)) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
end
