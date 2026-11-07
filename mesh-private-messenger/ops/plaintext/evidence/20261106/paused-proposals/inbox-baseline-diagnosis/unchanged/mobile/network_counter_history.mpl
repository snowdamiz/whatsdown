##! At most one immutable fact per service/current witness per configuration.
##! A concurrent refresh cannot erase a proven slash by replacing a display cache.
from Mobile.NetworkCounterPins import NetworkCounterPins, counter_integer
from Mobile.NetworkCounterState import NetworkBondObservation
from Storage.Blobs import blob_record_hash, load_blob
from Storage.Records import with_record_transaction
from Storage.Keys import local_context, seal_local, open_local

pub struct NetworkSlashFact do
  index :: Int
  slot :: U64
  timestamp :: U64
  digest :: Bytes
end

fn label(pins :: NetworkCounterPins, index :: Int) -> String do
  "network-counter/slash/v1/" <> Bytes.to_hex(pins.identity) <> "/" <> Int.to_string(index)
end

pub fn load_counter_slashes(path :: String,
  pins :: NetworkCounterPins,
  key :: borrow StorageKey) -> List<NetworkSlashFact>!String do
  let values = for index in 0..(List.length(pins.security.witnesses) + 1) do
    let name = label(pins, index)
    let ciphertext = case load_blob(path, name) do
      Err(error) -> if error == "local_state_not_found" do
        None
      else
        return Err(error)
      end
      Ok(value) -> Some(value)
    end
    case ciphertext do
      None
      Some(value) -> do
        let raw = open_local(value, key, local_context(name)?)?
        if Bytes.length(raw) != 52 || Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "4e534631" do
          return Err("invalid_counter_slash_history")
        end
        Some(NetworkSlashFact {
          index: index,
          slot: U64.parse(Bytes.read_uint_le(raw, 4, 8)?)?,
          timestamp: U64.parse(Bytes.read_uint_le(raw, 12, 8)?)?,
          digest: Bytes.slice(raw, 20, 32)?
        })
      end
    end
  end
  Ok(List.flat_map(values,
    fn(value) do
      case value do
        None -> []
        Some(fact) -> [fact]
      end
    end))
end

pub fn retain_counter_slashes(path :: String,
  pins :: NetworkCounterPins,
  key :: borrow StorageKey,
  observation :: NetworkBondObservation) -> Result<(), String> do
  let selected = List.filter(for index in 0..List.length(observation.rows) do
      index
    end,
    fn(index) do
      if index == 0 do
        observation.service_slashed
      else
        List.get(observation.rows, index).status == 3
      end
    end)
  let body = List.reduce([
      Bytes.from_utf8("NSF1"),
      Bytes.write_uint_le(U64.to_string(observation.slot), 8)?,
      Bytes.write_uint_le(U64.to_string(observation.timestamp), 8)?,
      observation.digest
    ],
    Ok(Bytes.empty()),
    fn(result, part) do Bytes.concat(result?, part) end)?
  let sealed = for index in selected do
    seal_local(body, key, local_context(label(pins, index))?)?
  end
  # The entire observed set commits atomically. Existing facts remain immutable;
  # a duplicate refresh does not erase its first source bank/digest.
  with_record_transaction(path,
    fn(database) do
      for at in 0..List.length(selected) do
        let name = label(pins, List.get(selected, at))
        Sqlite.execute_values(database,
          "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO NOTHING",
          [Text(blob_record_hash(database, name)?), Binary(List.get(sealed, at))])?
      end
      Ok(nil)
    end)
end

pub fn counter_history_mask(facts :: List<NetworkSlashFact>) -> Int do
  List.reduce(facts, 0, fn(sum, fact) do sum + power(fact.index) end)
end

fn power(index :: Int) -> Int do
  if index == 0 do
    1
  else
    2 * power(index - 1)
  end
end
