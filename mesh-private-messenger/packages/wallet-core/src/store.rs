use crate::{derive::derive, Error, MorseWalletCallbacksV1};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

pub(crate) const RECORD_BYTES: usize = 44;
pub(crate) const INDEX_LIMIT: u64 = 1 << 31;

pub(crate) struct Record {
    pub(crate) seed: Zeroizing<[u8; 32]>,
    next: u64,
}

impl Record {
    fn decode(bytes: &[u8; RECORD_BYTES]) -> Result<Self, Error> {
        if &bytes[..4] != b"MWL1" {
            return Err(Error::Storage);
        }
        let next = u64::from_le_bytes(bytes[36..].try_into().expect("fixed record"));
        if next > INDEX_LIMIT {
            return Err(Error::Storage);
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&bytes[4..36]);
        Ok(Self { seed, next })
    }
    fn encode(&self) -> Zeroizing<[u8; RECORD_BYTES]> {
        let mut bytes = Zeroizing::new([0; RECORD_BYTES]);
        bytes[..4].copy_from_slice(b"MWL1");
        bytes[4..36].copy_from_slice(&*self.seed);
        bytes[36..].copy_from_slice(&self.next.to_le_bytes());
        bytes
    }
    pub(crate) fn payment_key(&self) -> SigningKey {
        SigningKey::from_bytes(&derive(&*self.seed, &[44, 501, 0, 0]))
    }
    pub(crate) fn address(&self) -> [u8; 32] {
        self.payment_key().verifying_key().to_bytes()
    }
    pub(crate) fn bounty_key(&self, index: u64) -> Result<SigningKey, Error> {
        if index >= self.next || index >= INDEX_LIMIT {
            return Err(Error::Invalid);
        }
        Ok(SigningKey::from_bytes(&derive(
            &*self.seed,
            &[44, 501, 2147483647, index as u32],
        )))
    }
}

struct Locked<'a> {
    host: &'a MorseWalletCallbacksV1,
    held: bool,
}
impl<'a> Locked<'a> {
    fn acquire(host: &'a MorseWalletCallbacksV1) -> Result<Self, Error> {
        if unsafe { (host.acquire.expect("validated callback"))(host.context) } != 0 {
            return Err(Error::Storage);
        }
        Ok(Self { host, held: true })
    }
    fn load(&self) -> Result<Option<Record>, Error> {
        let mut bytes = Zeroizing::new([0; RECORD_BYTES]);
        let mut written = 0;
        let status = unsafe {
            (self.host.load.expect("validated callback"))(
                self.host.context,
                bytes.as_mut_ptr(),
                RECORD_BYTES as u64,
                &mut written,
            )
        };
        match (status, written) {
            (2, 0) => Ok(None),
            (0, 44) => Record::decode(&bytes).map(Some),
            _ => Err(Error::Storage),
        }
    }
    fn save(&self, record: &Record) -> Result<(), Error> {
        let bytes = record.encode();
        if unsafe {
            (self.host.replace.expect("validated callback"))(
                self.host.context,
                bytes.as_ptr(),
                RECORD_BYTES as u64,
            )
        } != 0
        {
            return Err(Error::Storage);
        }
        Ok(())
    }
    fn finish(mut self) -> Result<(), Error> {
        self.held = false;
        if unsafe { (self.host.release.expect("validated callback"))(self.host.context) } != 0 {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }
}
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        if self.held {
            unsafe {
                (self.host.release.expect("validated callback"))(self.host.context);
            }
        }
    }
}

pub(crate) fn read(host: &MorseWalletCallbacksV1) -> Result<Record, Error> {
    let guard = Locked::acquire(host)?;
    let value = guard.load()?.ok_or(Error::NotFound)?;
    guard.finish()?;
    Ok(value)
}
pub(crate) fn create(host: &MorseWalletCallbacksV1) -> Result<[u8; 32], Error> {
    let guard = Locked::acquire(host)?;
    if let Some(record) = guard.load()? {
        let address = record.address();
        guard.finish()?;
        return Ok(address);
    }
    guard.finish()?;
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed).map_err(|_| Error::Internal)?;
    let record = Record { seed, next: 0 };
    let address = record.address();
    if unsafe {
        (host.authorize.expect("validated callback"))(host.context, 1, address.as_ptr(), 32)
    } != 0
    {
        return Err(Error::Cancelled);
    }
    let guard = Locked::acquire(host)?;
    // Never overwrite a wallet created while the native prompt was open.
    if guard.load()?.is_some() {
        return Err(Error::Storage);
    }
    guard.save(&record)?;
    guard.finish()?;
    Ok(address)
}
pub(crate) fn reserve_bounty(host: &MorseWalletCallbacksV1) -> Result<Vec<u8>, Error> {
    let guard = Locked::acquire(host)?;
    let mut record = guard.load()?.ok_or(Error::NotFound)?;
    let index = record.next;
    if index >= INDEX_LIMIT {
        return Err(Error::Exhausted);
    }
    record.next = index + 1;
    guard.save(&record)?;
    guard.finish()?;
    // No public address escapes before the durable replacement acknowledged.
    let key = SigningKey::from_bytes(&derive(&*record.seed, &[44, 501, 2147483647, index as u32]));
    let mut output = Vec::with_capacity(40);
    output.extend_from_slice(&index.to_le_bytes());
    output.extend_from_slice(&key.verifying_key().to_bytes());
    Ok(output)
}
