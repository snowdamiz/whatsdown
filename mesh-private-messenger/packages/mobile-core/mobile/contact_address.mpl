from Mobile.Codec import random_bytes
from Protocol.V1 import ProtocolExtension
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local

##! The secret second deposit address a device shares only with contacts.
##!
##! A mailbox's public address is in the directory, so anyone can fill it. The
##! delivery service keeps part of every mailbox for envelopes sent to a second
##! address whose hash the device has published. This module keeps this
##! device's own address, hands it to contacts inside the encrypted channel,
##! and remembers the addresses contacts have handed over.
# The inner-envelope extension that carries the sender device's contact address.

pub fn contact_address_extension() -> Int do
  1
end

fn load_address(database_path :: String, wrapping_key :: borrow StorageKey, label :: String) -> Bytes!String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> do
      let value = open_local(blob, wrapping_key, local_context(label)?)?
      if Bytes.length(value) != 32 do
        Err("invalid_contact_address")
      else
        Ok(value)
      end
    end
  end
end

fn sealed_address(value :: Bytes, wrapping_key :: borrow StorageKey, label :: String) -> Bytes!String do
  seal_local(value, wrapping_key, local_context(label)?)
end

# This device's own address. A new one is only handed out once the directory has
# answered a publication that named it: until then the directory would not know
# where an envelope sent to it belongs.

pub fn confirmed_contact_address(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  load_address(database_path, wrapping_key, "contact-address/v1")
end

# What the next publication names, and what must be stored before it is sent:
# the address still awaiting an answer, else the confirmed one, else a new one.

pub fn published_contact_address(database_path :: String, wrapping_key :: borrow StorageKey) -> Result<(Bytes, List<String>, List<Bytes>), String> do
  let pending = load_address(database_path, wrapping_key, "contact-address-pending/v1")?
  if Bytes.length(pending) == 32 do
    Ok((pending, List.new(), List.new()))
  else
    let confirmed = confirmed_contact_address(database_path, wrapping_key)?
    if Bytes.length(confirmed) == 32 do
      Ok((confirmed, List.new(), List.new()))
    else
      let created = random_bytes(32)?
      Ok((created,
        ["contact-address-pending/v1"],
        [sealed_address(created, wrapping_key, "contact-address-pending/v1")?]))
    end
  end
end

# The directory answered a publication, so whatever address it named is live.

pub fn confirmed_contact_address_writes(database_path :: String, wrapping_key :: borrow StorageKey) -> Result<(List<String>, List<Bytes>, List<String>), String> do
  let pending = load_address(database_path, wrapping_key, "contact-address-pending/v1")?
  if Bytes.length(pending) != 32 do
    Ok((List.new(), List.new(), List.new()))
  else
    Ok((["contact-address/v1"],
      [sealed_address(pending, wrapping_key, "contact-address/v1")?],
      ["contact-address-pending/v1"]))
  end
end

# A new address to publish. The directory retires the old one when it learns of
# this one, which takes the contact share away from everyone holding the old
# address until they are handed the new one; that is the point when a
# conversation is blocked.

pub fn rotated_contact_address_writes(wrapping_key :: borrow StorageKey) -> Result<(List<String>, List<Bytes>), String> do
  Ok((["contact-address-pending/v1"],
    [sealed_address(random_bytes(32)?, wrapping_key, "contact-address-pending/v1")?]))
end

# What a message to a contact carries: this device's confirmed address, if any.

pub fn outgoing_extensions(database_path :: String, wrapping_key :: borrow StorageKey) -> List<ProtocolExtension>!String do
  let address = confirmed_contact_address(database_path, wrapping_key)?
  if Bytes.length(address) != 32 do
    Ok(List.new())
  else
    Ok([ProtocolExtension { id: contact_address_extension(), mandatory: false, value: address }])
  end
end

fn peer_label(public_address :: Bytes) -> String do
  "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(public_address))}"
end

fn owner_label(contact_address :: Bytes) -> String do
  "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(contact_address))}"
end

# Where to send an envelope for the device whose public address this is: the
# contact address it handed over, or the public one.

pub fn deposit_address(database_path :: String,
  wrapping_key :: borrow StorageKey,
  public_address :: Bytes) -> Bytes!String do
  let known = load_address(database_path, wrapping_key, peer_label(public_address))?
  if Bytes.length(known) == 32 do
    Ok(known)
  else
    Ok(public_address)
  end
end

fn extension_value(values :: List<ProtocolExtension>, index :: Int) -> Bytes do
  if index >= List.length(values) do
    Bytes.empty()
  else
    let value = List.get(values, index)
    if value.id == contact_address_extension() do
      value.value
    else
      extension_value(values, index + 1)
    end
  end
end

# A message from the device at `public_address` may hand over its contact
# address. It is only a hint about where to send: a wrong one costs the sender
# of the hint their own delivery, and is forgotten the first time the directory
# refuses it.

pub fn learned_contact_address_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  public_address :: Bytes,
  extensions :: List<ProtocolExtension>) -> Result<(List<String>, List<Bytes>, List<String>), String> do
  let offered = extension_value(extensions, 0)
  if Bytes.length(offered) != 32 || Bytes.length(public_address) != 32 || Bytes.secure_equals(offered,
    public_address) do
    Ok((List.new(), List.new(), List.new()))
  else
    let known = load_address(database_path, wrapping_key, peer_label(public_address))?
    if Bytes.secure_equals(known, offered) do
      Ok((List.new(), List.new(), List.new()))
    else
      let forgotten = if Bytes.length(known) == 32 do
        [owner_label(known)]
      else
        List.new()
      end
      Ok(([peer_label(public_address), owner_label(offered)],
        [
          sealed_address(offered, wrapping_key, peer_label(public_address))?,
          sealed_address(public_address, wrapping_key, owner_label(offered))?
        ],
        forgotten))
    end
  end
end

# The directory refused an envelope for good. If it was addressed to a contact
# address, stop using that address: the next message goes to the public one.

pub fn refused_address_removals(database_path :: String,
  wrapping_key :: borrow StorageKey,
  address :: Bytes) -> List<String>!String do
  let owner = load_address(database_path, wrapping_key, owner_label(address))?
  if Bytes.length(owner) != 32 do
    Ok(List.new())
  else
    Ok([owner_label(address), peer_label(owner)])
  end
end
