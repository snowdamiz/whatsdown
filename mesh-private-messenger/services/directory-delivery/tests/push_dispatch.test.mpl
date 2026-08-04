from Runtime.PushDispatch import broker_authorization

test("directory push dispatch requires a safe broker bearer credential") do
  let secret = "0123456789abcdef0123456789abcdef"
  case broker_authorization(secret) do
    Err( _) -> assert(false)
    Ok( value) -> assert(value == "Bearer " <> secret)
  end
  case broker_authorization("") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case broker_authorization("0123456789abcdef0123456789abc\n") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
end
