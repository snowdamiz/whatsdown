//! Historical WK keys only. The actual receiving handler supplies its native
//! database path and compares a fresh Core identity before calling these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProfileIdentity { account:[u8;32], device:[u8;16] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyKind { ReadState,NotificationState,ReceiptMarks,ReadReceipts,NotificationPreview }
impl LegacyKind {
    pub(crate) fn parse(value:&str)->Result<Self,&'static str> {
        match value { "read-state"=>Ok(Self::ReadState),"notification-state"=>Ok(Self::NotificationState),
            "receipt-marks"=>Ok(Self::ReceiptMarks),"read-receipts"=>Ok(Self::ReadReceipts),
            "notification-preview"=>Ok(Self::NotificationPreview),_=>Err("invalid_legacy_kind") }
    }
    fn label(self)->&'static str { match self { Self::ReadState=>"read-state",Self::NotificationState=>"notification-state",
        Self::ReceiptMarks=>"receipt-marks",Self::ReadReceipts=>"read-receipts",Self::NotificationPreview=>"notification-preview" } }
}
fn vector<'a>(bytes:&mut &'a [u8],maximum:usize)->Result<&'a [u8],&'static str> {
    let header:[u8;4]=bytes.get(..4).ok_or("invalid_profile")?.try_into().map_err(|_|"invalid_profile")?;
    let count=u32::from_be_bytes(header) as usize;
    if count>maximum { return Err("invalid_profile"); }
    let end=4usize.checked_add(count).ok_or("invalid_profile")?;
    let value=bytes.get(4..end).ok_or("invalid_profile")?;
    *bytes=bytes.get(end..).ok_or("invalid_profile")?;Ok(value)
}
fn hex(bytes:&[u8])->String {
    const DIGITS:&[u8;16]=b"0123456789abcdef";let mut text=String::with_capacity(bytes.len()*2);
    for byte in bytes { text.push(DIGITS[(byte>>4) as usize] as char);text.push(DIGITS[(byte&15) as usize] as char); }text
}
impl ProfileIdentity {
    // Exact actual ProfileSummary: four length-prefixed vectors and no count,
    // including the opaque profile payload. Username/opaque content are never
    // used to select storage keys or treated as native authority.
    pub(crate) fn parse(mut bytes:&[u8])->Result<Self,&'static str> {
        std::str::from_utf8(vector(&mut bytes,64)?).map_err(|_|"invalid_profile")?;
        let account=vector(&mut bytes,32)?.try_into().map_err(|_|"invalid_profile")?;
        let device=vector(&mut bytes,16)?.try_into().map_err(|_|"invalid_profile")?;
        vector(&mut bytes,36006)?;
        if !bytes.is_empty() { return Err("invalid_profile"); }
        Ok(Self { account,device })
    }
    pub(crate) fn legacy_key(self,database:&str,kind:LegacyKind)->Result<String,&'static str> {
        if database.is_empty() || database.len()>4096 || database.contains('\0') { return Err("invalid_database_path"); }
        Ok(format!("{}/{}/v1/{}",database,kind.label(),hex(&self.account)))
    }
    pub(crate) fn notification_key(self,database:&str)->Result<String,&'static str> {
        if database.is_empty() || database.len()>4096 || database.contains('\0') { return Err("invalid_database_path"); }
        Ok(format!("{}/notifications-enabled/{}/{}",database,hex(&self.account),hex(&self.device)))
    }
    pub(crate) fn account_hex(self)->String { hex(&self.account) }
}
