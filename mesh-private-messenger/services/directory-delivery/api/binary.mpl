from Protocol.V1 import decode_device_revocation, decode_directory_entry, decode_directory_lookup, decode_mailbox_ack, decode_mailbox_fetch, decode_outer_envelope, encode_delivery_batch, encode_device_set, encode_directory_entry
from Storage.Delivery import DeliveryInsert, acknowledge_mailbox, enqueue_envelope, fetch_mailbox
from Storage.Devices import DeviceWrite, register_device, resolve_devices, revoke_device
from Storage.Directory import register_directory, resolve_directory

pub struct BinaryResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> BinaryResult do
  BinaryResult {
    status : status,
    body : body
  }
end

fn empty(status :: Int) -> BinaryResult do
  response(status, Bytes.empty())
end

pub fn register_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_entry(body) do
    Err( _) -> empty(400)
    Ok( entry) -> case register_directory(pool, entry) do
      Err( _) -> empty(500)
      Ok( _) -> empty(201)
    end
  end
end

pub fn resolve_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_lookup(body) do
    Err( _) -> empty(400)
    Ok( username) -> case resolve_directory(pool, username) do
      Err( _) -> empty(500)
      Ok( None) -> empty(404)
      Ok( Some( entry)) -> case encode_directory_entry(entry) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

fn device_write(result :: Result < DeviceWrite, String >) -> BinaryResult do
  case result do
    Err( _) -> empty(500)
    Ok( DeviceAccepted) -> empty(201)
    Ok( DeviceUnchanged) -> empty(200)
    Ok( DeviceConflict) -> empty(409)
    Ok( DeviceInvalid) -> empty(400)
  end
end

pub fn register_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_entry(body) do
    Err( _) -> empty(400)
    Ok( entry) -> device_write(register_device(pool, entry))
  end
end

pub fn resolve_devices_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_lookup(body) do
    Err( _) -> empty(400)
    Ok( username) -> case resolve_devices(pool, username) do
      Err( _) -> empty(500)
      Ok( None) -> empty(404)
      Ok( Some( devices)) -> case encode_device_set(devices) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

pub fn revoke_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_device_revocation(body) do
    Err( _) -> empty(400)
    Ok( revocation) -> case revoke_device(pool, revocation) do
      Err( _) -> empty(500)
      Ok( DeviceAccepted) -> empty(200)
      Ok( DeviceUnchanged) -> empty(200)
      Ok( DeviceConflict) -> empty(409)
      Ok( DeviceInvalid) -> empty(400)
    end
  end
end

pub fn submit_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_outer_envelope(body) do
    Err( _) -> empty(400)
    Ok( envelope) -> case enqueue_envelope(pool, envelope) do
      Err( _) -> empty(500)
      Ok( Accepted) -> empty(202)
      Ok( Duplicate) -> empty(200)
      Ok( MailboxFull) -> empty(429)
      Ok( MailboxRevoked) -> empty(410)
      Ok( RateLimited) -> empty(429)
    end
  end
end

pub fn fetch_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_fetch(body) do
    Err( _) -> empty(400)
    Ok( request) -> case fetch_mailbox(pool, request) do
      Err( _) -> empty(500)
      Ok( deliveries) -> case encode_delivery_batch(deliveries) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

pub fn acknowledge_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_ack(body) do
    Err( _) -> empty(400)
    Ok( ack) -> case acknowledge_mailbox(pool, ack) do
      Err( _) -> empty(500)
      Ok( _) -> empty(200)
    end
  end
end
