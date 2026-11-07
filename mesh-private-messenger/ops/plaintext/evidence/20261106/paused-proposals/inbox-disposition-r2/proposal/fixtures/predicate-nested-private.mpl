from Mobile.Inbox import permanent_direct_delivery_error, header_selection_unfinished

struct ErrorBox do
  error :: Plaintext<String>
end

fn nested_result(value :: Plaintext<Result<String, String>>) -> Int do
  let error = case value do
    Ok(text) -> text
    Err(text) -> text
  end
  let matched = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"),
    Bytes.from_utf8(if matched do "yes" else "no" end))
end

fn nested_box(value :: ErrorBox) -> Int do
  let matched = header_selection_unfinished(value.error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"),
    Bytes.from_utf8(if matched do "yes" else "no" end))
end

fn nested_list(values :: List<Plaintext<String>>) -> Int do
  let matched = permanent_direct_delivery_error(List.head(values))
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"),
    Bytes.from_utf8(if matched do "yes" else "no" end))
end

fn selected_error(flag :: Plaintext<Bool>) -> Int do
  let error = if flag do "view_once_reference_refused" else "unknown_error" end
  let matched = permanent_direct_delivery_error(error)
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"),
    Bytes.from_utf8(if matched do "yes" else "no" end))
end

fn unfinished_branch(error :: Plaintext<String>) -> Int do
  if header_selection_unfinished(error) do
    Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant"))
  else
    0
  end
end

fn main() do nil end
