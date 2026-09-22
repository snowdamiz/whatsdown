from Groups.SenderKeys import advance_sender, fork_keys, receive_key, sender_message_key

##! Groups.GroupMessages for the bounded messenger group protocol.

from Binary.Reader import BinaryReader
from Groups.GroupCodec import (
  group_append,
  group_byte,
  group_join,
  group_vector,
  group_wire_end,
  group_wire_fixed,
  group_wire_start,
  group_wire_u16,
  group_wire_u32,
  group_wire_u64,
  group_wire_u8,
  group_wire_vector,
  group_write_u16,
  group_write_u32,
  group_write_u64
)
from Groups.Mls import (
  EncryptMessageContext,
  GroupDecryptOutcome,
  GroupEncryptOutcome,
  GroupError,
  GroupMessage,
  GroupReadBytes,
  GroupReadInt,
  GroupReadWide,
  GroupState,
  OpenMessageContext,
  SenderGeneration,
  TreeMessageContext
)
from Groups.Tree import GroupTree, member_at, tree_hash
from Transport.Padding import pad_message, unpad_message

fn validate_message_shape(value :: GroupMessage) -> Result <(), GroupError > do
  let valid = (value.version == 1 || value.version == 2 || value.version == 3 || value.version == 4) && value.suite == 3 && Bytes.length(value.group_id) == 32 && Bytes.length(value.tree_hash) == 32 && value.sender_leaf >= 0 && value.sender_leaf < 64 && value.generation >= 0 && Bytes.length(value.nonce) == 12 && Bytes.length(value.ciphertext) >= 16 && Bytes.length(value.ciphertext) <= 65362 && Bytes.length(value.signature.bytes) == 64
  if valid do
    Ok(nil)
  else
    Err(InvalidGroup)
  end
end

pub fn encode_group_message(value :: GroupMessage) -> Bytes ! GroupError do
  validate_message_shape(value) ?
  group_join([group_byte(1) ?, Bytes.from_utf8("GMS"), group_byte(value.version) ?, group_write_u16(value.suite) ?, value.group_id, group_write_u64(value.epoch) ?, value.tree_hash, group_write_u16(value.sender_leaf) ?, group_write_u32(value.generation) ?, value.nonce, group_vector(value.ciphertext) ?, value.signature.bytes],
  0,
  Bytes.empty())
end

pub fn decode_group_message(input :: Bytes) -> GroupMessage ! GroupError do
  let version = group_wire_u8(group_wire_start(input, 65527, "GMS") ?) ?
  let suite = group_wire_u16(version.state) ?
  let group_id = group_wire_fixed(suite.state, 32) ?
  let epoch = group_wire_u64(group_id.state) ?
  let tree = group_wire_fixed(epoch.state, 32) ?
  let sender = group_wire_u16(tree.state) ?
  let generation = group_wire_u32(sender.state) ?
  let nonce = group_wire_fixed(generation.state, 12) ?
  let ciphertext = group_wire_vector(nonce.state, 65362) ?
  let signature = group_wire_fixed(ciphertext.state, 64) ?
  group_wire_end(signature.state) ?
  let value = GroupMessage {
    version : version.value,
    suite : suite.value,
    group_id : group_id.value,
    epoch : epoch.value,
    tree_hash : tree.value,
    sender_leaf : sender.value,
    generation : generation.value,
    nonce : nonce.value,
    ciphertext : ciphertext.value,
    signature : Signature { bytes : signature.value }
  }
  validate_message_shape(value) ?
  Ok(value)
end

fn message_context(version :: Int,
suite :: Int,
group_id :: Bytes,
epoch :: U64,
current_tree_hash :: Bytes,
sender_leaf :: Int,
generation :: Int,
nonce :: Bytes,
caller_data :: Bytes) -> Bytes ! GroupError do
  group_join([Bytes.from_utf8("mesh-mls/v1/group-message"), group_byte(version) ?, group_write_u16(suite) ?, group_id, group_write_u64(epoch) ?, current_tree_hash, group_write_u16(sender_leaf) ?, group_write_u32(generation) ?, nonce, caller_data],
  0,
  Bytes.empty())
end

fn message_info(sender_leaf :: Int, generation :: Int) -> Bytes ! GroupError do
  group_join([Bytes.from_utf8("mesh-mls/v1/message-key"), group_write_u16(sender_leaf) ?, group_write_u32(generation) ?],
  0,
  Bytes.empty())
end

fn message_key(material :: SecretBytes) -> AeadKey ! GroupError do
  case Crypto.aead_key(material) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn consume_message_key(key :: consume AeadKey) do
  nil
end

fn signed_message_bytes(message :: GroupMessage, context :: Bytes) -> Bytes ! GroupError do
  group_join([context, group_vector(message.ciphertext) ?], 0, Bytes.empty())
end

fn tree_message_context(tree :: borrow GroupTree, sender_leaf :: Int) -> TreeMessageContext ! GroupError do
  let sender = case member_at(tree, sender_leaf) do
    Err(error) -> Err(TreeFailure(error))
    Ok(value) -> Ok(value)
  end ?
  Ok(TreeMessageContext {
    hash : tree_hash(tree),
    sender : sender
  })
end

fn open_message_context(state :: borrow GroupState, message :: GroupMessage) -> OpenMessageContext ! GroupError do
  let suite = state.suite
  let group_id = state.group_id
  let epoch = state.epoch
  let last_generation = received_generation(state.received_generations, message.sender_leaf, 0)
  Ok(OpenMessageContext {
    suite : suite,
    group_id : group_id,
    epoch : epoch,
    last_generation : last_generation,
    tree : tree_message_context(state.tree, message.sender_leaf) ?
  })
end

fn seal_epoch_message(signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
nonce :: Bytes,
info :: Bytes,
context :: Bytes,
metadata :: EncryptMessageContext,
material :: SecretBytes,
version :: Int) -> GroupMessage ! GroupError do
  let key = message_key(material) ?
  let sealed = Crypto.aead_seal(key, nonce, context, plaintext)
  consume_message_key(key)
  let ciphertext = case sealed do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  let unsigned = GroupMessage {
    version : version,
    suite : metadata.suite,
    group_id : metadata.group_id,
    epoch : metadata.epoch,
    tree_hash : metadata.tree_hash,
    sender_leaf : metadata.sender_leaf,
    generation : metadata.generation,
    nonce : nonce,
    ciphertext : ciphertext,
    signature : Signature { bytes : Bytes.empty() }
  }
  let unsigned_bytes = signed_message_bytes(unsigned, context) ?
  let signature = case Crypto.sign(signing_key, unsigned_bytes) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  Ok(% {unsigned | signature : signature })
end

fn prepare_group_message(state :: borrow GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes,
version :: Int) -> GroupMessage ! GroupError do
  let maximum = if version == 4 do
    65290
  else
    65342
  end
  if (version != 3 && version != 4) || state.version != 2 || Bytes.length(plaintext) > maximum || Bytes.length(caller_data) > 4096 || state.next_generation < 0 || state.next_generation >= 256 do
    Err(InvalidGroup)
  else
    let nonce = case Crypto.random_bytes(12) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(value) -> Ok(value)
    end ?
    let metadata = EncryptMessageContext {
      suite : state.suite,
      group_id : state.group_id,
      epoch : state.epoch,
      tree_hash : state.tree_hash_cache,
      sender_leaf : state.local_leaf,
      generation : state.next_generation
    }
    let info = message_info(metadata.sender_leaf, metadata.generation) ?
    let context = message_context(version,
    metadata.suite,
    metadata.group_id,
    metadata.epoch,
    metadata.tree_hash,
    metadata.sender_leaf,
    metadata.generation,
    nonce,
    caller_data) ?
    let padded = if version == 4 do
      Ok(plaintext)
    else
      case pad_message(plaintext, 190) do
        Err(_) -> Err(InvalidGroup)
        Ok(value) -> Ok(value)
      end
    end ?
    let message = seal_epoch_message(signing_key,
    padded,
    nonce,
    info,
    context,
    metadata,
    sender_message_key(state.key_material.sender_chains,
    state.group_id,
    state.local_leaf,
    state.next_generation) ?,
    version) ?
    let sender = case member_at(state.tree, state.local_leaf) do
      Err(error) -> Err(TreeFailure(error))
      Ok(value) -> Ok(value)
    end ?
    let signed = signed_message_bytes(message, context) ?
    case Crypto.verify(sender.signing_public_key, signed, message.signature) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(false) -> Err(AuthenticationRejected)
      Ok(true) -> Ok(message)
    end
  end
end

pub fn encrypt_group_message(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes) -> GroupEncryptOutcome do
  encrypt_group_message_version(state, signing_key, plaintext, caller_data, 3)
end

# Version 4 delegates padding to the encrypted recipient transport.

pub fn encrypt_group_message_for_transport(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes) -> GroupEncryptOutcome do
  encrypt_group_message_version(state, signing_key, plaintext, caller_data, 4)
end

fn encrypt_group_message_version(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes,
version :: Int) -> GroupEncryptOutcome do
  case prepare_group_message(state, signing_key, plaintext, caller_data, version) do
    Err(error) -> GroupEncryptRejected(state, error)
    Ok(message) -> do
      case advance_sender(state.key_material.sender_chains,
      state.group_id,
      state.local_leaf,
      state.next_generation) do
        Err(error) -> GroupEncryptRejected(state, error)
        Ok(chains) -> case fork_keys(state.key_material.skipped_keys) do
          Err(error) -> do
            discard_keys(chains)
            GroupEncryptRejected(state, error)
          end
          Ok(skipped) -> do
            let next :: GroupState = replace_keys(state, chains, skipped)
            let next_generation = next.next_generation + 1
            GroupMessageEncrypted(% {next | next_generation : next_generation }, message)
          end
        end
      end
    end
  end
end

fn received_generation(values :: List < SenderGeneration >, leaf_index :: Int, index :: Int) -> Int do
  if index >= List.length(values) do
    -1
  else
    let value = List.get(values, index)
    if value.leaf_index == leaf_index do
      value.generation
    else
      received_generation(values, leaf_index, index + 1)
    end
  end
end

fn record_generation(values :: List < SenderGeneration >,
leaf_index :: Int,
generation :: Int,
index :: Int,
output :: List < SenderGeneration >) -> List < SenderGeneration > do
  if index >= List.length(values) do
    if received_generation(values, leaf_index, 0) < 0 do
      List.append(output,
      SenderGeneration {
        leaf_index : leaf_index,
        generation : generation
      })
    else
      output
    end
  else
    let value = List.get(values, index)
    let next = if value.leaf_index == leaf_index do
      SenderGeneration {
        leaf_index : leaf_index,
        generation : if generation > value.generation do
          generation
        else
          value.generation
        end
      }
    else
      value
    end
    record_generation(values, leaf_index, generation, index + 1, List.append(output, next))
  end
end

fn open_group_plaintext(key :: borrow AeadKey, message :: GroupMessage, context :: Bytes) -> Bytes ! GroupError do
  let plaintext = case Crypto.aead_open(key, message.nonce, context, message.ciphertext) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  if message.version == 1 || message.version == 4 do
    Ok(plaintext)
  else
    case unpad_message(plaintext, 190) do
      Err(_) -> Err(InvalidGroup)
      Ok(value) -> Ok(value)
    end
  end
end

fn open_epoch_message(state :: borrow GroupState, message :: GroupMessage, caller_data :: Bytes) -> Result <(Bytes, SecretMap, SecretMap), GroupError > do
  let public = open_message_context(state, message) ?
  let wrong_header = !((state.version == 1 && (message.version == 1 || message.version == 2)) || (state.version == 2 && (message.version == 3 || message.version == 4))) || (state.version == 2 && message.sender_leaf == state.local_leaf) || message.suite != public.suite || !Bytes.secure_equals(message.group_id,
  public.group_id) || U64.compare(message.epoch, public.epoch) != 0 || !Bytes.secure_equals(message.tree_hash,
  public.tree.hash) || message.sender_leaf < 0 || message.sender_leaf >= 64 || message.generation < 0 || Bytes.length(message.nonce) != 12 || Bytes.length(message.ciphertext) < 16 || Bytes.length(message.ciphertext) > 65362 || Bytes.length(caller_data) > 4096
  if wrong_header do
    return Err(InvalidGroup)
  end
  if state.version == 1 && message.generation <= public.last_generation do
    return Err(Replay)
  end
  let context = message_context(message.version,
  public.suite,
  public.group_id,
  public.epoch,
  public.tree.hash,
  message.sender_leaf,
  message.generation,
  message.nonce,
  caller_data) ?
  let signed = signed_message_bytes(message, context) ?
  case Crypto.verify(public.tree.sender.signing_public_key, signed, message.signature) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(false) -> Err(AuthenticationRejected)
    Ok(true) -> Ok(nil)
  end ?
  if state.version == 1 do
    let info = message_info(message.sender_leaf, message.generation) ?
    let material = case Crypto.hkdf_sha256(state.key_material.epoch_secret,
    public.group_id,
    info,
    32) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(value) -> Ok(value)
    end ?
    let key = message_key(material) ?
    Ok((open_group_plaintext(key, message, context) ?,
    fork_keys(state.key_material.sender_chains) ?,
    fork_keys(state.key_material.skipped_keys) ?))
  else
    let (chains, skipped, material) = receive_key(state.key_material,
    public.group_id,
    message.sender_leaf,
    message.generation,
    public.last_generation) ?
    let key = message_key(material) ?
    Ok((open_group_plaintext(key, message, context) ?, chains, skipped))
  end
end

pub fn decrypt_group_message(state :: consume GroupState,
message :: GroupMessage,
caller_data :: Bytes) -> GroupDecryptOutcome do
  case open_epoch_message(state, message, caller_data) do
    Err(error) -> MessageRejected(state, error)
    Ok(value) -> do
      let (plaintext, chains, skipped) = value
      let state :: GroupState = replace_keys(state, chains, skipped)
      let generations = record_generation(state.received_generations,
      message.sender_leaf,
      message.generation,
      0,
      List.new())
      MessageOpened(% {state | received_generations : generations }, plaintext)
    end
  end
end

# ponytail: sender replay tracking is a 64-entry scan; use an indexed persistent map if the fixed group cap grows.

fn replace_keys(state :: consume GroupState,
chains :: consume SecretMap,
skipped :: consume SecretMap) -> GroupState do
  let version = state.version
  let suite = state.suite
  let group_id = state.group_id
  let epoch = state.epoch
  let tree = state.tree
  let tree_hash_cache = state.tree_hash_cache
  let transcript_hash = state.transcript_hash
  let local_leaf = state.local_leaf
  let next_generation = state.next_generation
  let received_generations = state.received_generations
  let extensions = state.extensions
  let policy = state.policy
  let snapshot_version = state.snapshot_version
  let material = state.key_material
  GroupState {
    version : version,
    suite : suite,
    group_id : group_id,
    epoch : epoch,
    tree : tree,
    tree_hash_cache : tree_hash_cache,
    transcript_hash : transcript_hash,
    key_material : % {material | sender_chains : chains, skipped_keys : skipped },
    local_leaf : local_leaf,
    next_generation : next_generation,
    received_generations : received_generations,
    extensions : extensions,
    policy : policy,
    snapshot_version : snapshot_version
  }
end

fn discard_keys(keys :: consume SecretMap) do
  nil
end
