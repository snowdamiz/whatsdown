from Storage.C2spPush import retry_size_for_test

test("C2SP size retries require one canonical bounded decimal line") do
  assert(retry_size_for_test(Bytes.from_utf8("0\n"), 7) == Ok(0))
  assert(retry_size_for_test(Bytes.from_utf8("7\n"), 7) == Ok(7))
  assert(retry_size_for_test(Bytes.from_utf8("4294967295\n"), 4294967295) == Ok(4294967295))
  for value in ["", "0", "00\n", "01\n", "-1\n", "+1\n", "1\r\n", " 1\n", "1 \n", "1\n\n", "8\n", "4294967296\n", "999999999999999999999999\n"] do
    assert(retry_size_for_test(Bytes.from_utf8(value), 7) == Err("invalid C2SP witness size"))
  end
end
