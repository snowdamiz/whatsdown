from Mobile.Inbox import permanent_direct_delivery_error, header_selection_unfinished

fn permanent_bool_body(error :: Plaintext<String>) -> Int do
  let verdict :: Bool = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn permanent_branch_constant(error :: Plaintext<String>) -> Int do
  let verdict :: Bool = permanent_direct_delivery_error(error)
  if verdict do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end

fn permanent_selected_error(flag :: Plaintext<Bool>) -> Int do
  let error = if flag do "wrong_mailbox" else "unknown_future_error" end
  let verdict :: Bool = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn permanent_known_permanent() -> Int do
  let error :: Plaintext<String> = "view_once_reference_refused"
  let verdict :: Bool = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn permanent_known_header() -> Int do
  let error :: Plaintext<String> = "header_selection_pending"
  let verdict :: Bool = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn permanent_unknown() -> Int do
  let error :: Plaintext<String> = "unknown_future_error"
  let verdict :: Bool = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn unfinished_bool_body(error :: Plaintext<String>) -> Int do
  let verdict :: Bool = header_selection_unfinished(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn unfinished_branch_constant(error :: Plaintext<String>) -> Int do
  let verdict :: Bool = header_selection_unfinished(error)
  if verdict do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end

fn unfinished_selected_error(flag :: Plaintext<Bool>) -> Int do
  let error = if flag do "wrong_mailbox" else "unknown_future_error" end
  let verdict :: Bool = header_selection_unfinished(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn unfinished_known_permanent() -> Int do
  let error :: Plaintext<String> = "view_once_reference_refused"
  let verdict :: Bool = header_selection_unfinished(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn unfinished_known_header() -> Int do
  let error :: Plaintext<String> = "header_selection_pending"
  let verdict :: Bool = header_selection_unfinished(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn unfinished_unknown() -> Int do
  let error :: Plaintext<String> = "unknown_future_error"
  let verdict :: Bool = header_selection_unfinished(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(verdict)))
end

fn explicit_bool_body(flag :: Plaintext<Bool>) -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8(String.from(flag)))
end

fn explicit_bool_branch_constant(flag :: Plaintext<Bool>) -> Int do
  if flag do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end

fn main() do nil end
