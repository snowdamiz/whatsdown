//! Closed IPC input; content never selects native account, owner, or request IDs.
use serde_json::{Map, Value};
use zeroize::Zeroizing;
pub(crate) struct PublishNotice {
    pub(crate) title: Zeroizing<String>,
    pub(crate) body: Zeroizing<String>,
    pub(crate) scope: Zeroizing<String>,
}
fn object(value: &Value) -> Result<&Map<String, Value>, &'static str> {
    let object = value.as_object().ok_or("invalid_notification_request")?;
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("invalid_notification_request");
    }
    Ok(object)
}
fn text<'a>(value: &'a Map<String, Value>, key: &str, maximum: usize) -> Result<&'a str, &'static str> {
    let text = value.get(key).and_then(Value::as_str).ok_or("invalid_notification_request")?;
    if text.len() > maximum || text.contains('\0') { return Err("invalid_notification_request"); }
    Ok(text)
}
impl PublishNotice {
    pub(crate) fn parse(value: &Value) -> Result<Self, &'static str> {
        let value = object(value)?;
        if value.len() != 6 || value.get("mention").and_then(Value::as_bool).is_none()
            || text(value, "id", 256)?.is_empty() { return Err("invalid_notification_request"); }
        let title = text(value, "title", 4096)?;
        let body = text(value, "body", 8192)?;
        let scope = text(value, "scope", 70)?;
        let hex = match scope.strip_prefix("chat/") {
            Some(hex) if hex.len() == 32 => hex,
            _ => scope.strip_prefix("group/").filter(|hex| hex.len() == 64)
                .ok_or("invalid_notification_request")?,
        };
        if !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err("invalid_notification_request");
        }
        Ok(Self { title: Zeroizing::new(title.to_owned()), body: Zeroizing::new(body.to_owned()), scope: Zeroizing::new(scope.to_owned()) })
    }
}
pub(crate) fn parse_take(value: &Value) -> Result<(), &'static str> {
    if object(value)?.len() != 1 { return Err("invalid_notification_request"); }
    Ok(())
}
