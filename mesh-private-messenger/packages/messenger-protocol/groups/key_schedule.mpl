##! Groups.KeySchedule for the bounded messenger group protocol.

from Groups.CommitWire import group_extensions_bytes, group_policy_bytes
from Groups.GroupCodec import group_append, group_byte, group_join, group_tree_path_error, group_tree_resolution_error, group_write_u16
from Groups.Mls import (
  GeneratedTreeKemPath,
  GroupError,
  GroupEpochKeys,
  GroupTransparencyPolicy,
  OpenedPathSecret,
  TreeKemCiphertext,
  TreeKemKeyMaterial,
  TreeKemPathPatch,
  TreeKemUpdateNode,
  TreeKemUpdatePath
)
from Groups.Tree import (
  GroupTree,
  GroupTreeError,
  TreeKemParentNode,
  TreeKemResolutionNode,
  copath,
  direct_path,
  resolution,
  member_at
)

pub fn group_hpke_info() -> Bytes do
  Bytes.from_utf8("mesh-mls/v1/path-secret")
end

pub fn group_path_aad(context :: Bytes, level :: Int, recipient_node :: Int) -> Bytes ! GroupError do
  group_join([context, group_byte(level) ?, group_write_u16(recipient_node) ?], 0, Bytes.empty())
end

pub fn group_welcome_context(context :: Bytes,
extensions :: List < Int >,
policy :: GroupTransparencyPolicy) -> Bytes ! GroupError do
  group_join([Bytes.from_utf8("mesh-mls/v1/welcome"), context, group_extensions_bytes(extensions) ?, group_policy_bytes(policy) ?],
  0,
  Bytes.empty())
end

pub fn group_destroy_private(value :: consume X25519PrivateKey) do
  nil
end

fn fresh_x25519() -> X25519KeyPair ! GroupError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

pub fn group_base_key_material(epoch_secret :: SecretBytes,
leaf_private_key :: consume X25519PrivateKey) -> TreeKemKeyMaterial ! GroupError do
  let level0 = fresh_x25519() ?
  let level1 = fresh_x25519() ?
  let level2 = fresh_x25519() ?
  let level3 = fresh_x25519() ?
  let level4 = fresh_x25519() ?
  let level5 = fresh_x25519() ?
  Ok(TreeKemKeyMaterial {
    sender_chains : group_empty_keys() ?,
    skipped_keys : group_empty_keys() ?,
    epoch_secret : epoch_secret,
    leaf_private_key : leaf_private_key,
    level0_private_key : level0.private_key,
    level1_private_key : level1.private_key,
    level2_private_key : level2.private_key,
    level3_private_key : level3.private_key,
    level4_private_key : level4.private_key,
    level5_private_key : level5.private_key,
    available_levels : List.new()
  })
end

fn derive_path_secret(value :: borrow SecretBytes) -> SecretBytes ! GroupError do
  case Crypto.hkdf_sha256(value, Bytes.empty(), Bytes.from_utf8("mesh-mls/v1/path"), 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end
end

fn derive_node_key(value :: borrow SecretBytes, node_index :: Int) -> X25519KeyPair ! GroupError do
  let info = group_append(Bytes.from_utf8("mesh-mls/v1/node"), group_write_u16(node_index) ?) ?
  let material = case Crypto.hkdf_sha256(value, Bytes.empty(), info, 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end ?
  case Crypto.x25519_from_secret(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( pair) -> Ok(pair)
  end
end

# ponytail: six explicit fields match the protocol's fixed 64-leaf ceiling; use a resource-aware vector if that ceiling grows.

pub fn group_generate_treekem_path(committer_leaf :: Int) -> GeneratedTreeKemPath ! GroupError do
  let path = group_tree_path_error(direct_path(committer_leaf)) ?
  let leaf = fresh_x25519() ?
  let secret0 = case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let secret1 = derive_path_secret(secret0) ?
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key0 = derive_node_key(secret0, List.get(path, 0)) ?
  let key1 = derive_node_key(secret1, List.get(path, 1)) ?
  let key2 = derive_node_key(secret2, List.get(path, 2)) ?
  let key3 = derive_node_key(secret3, List.get(path, 3)) ?
  let key4 = derive_node_key(secret4, List.get(path, 4)) ?
  let key5 = derive_node_key(secret5, List.get(path, 5)) ?
  let leaf_public_key = leaf.public_key
  let key0_public = key0.public_key
  let key1_public = key1.public_key
  let key2_public = key2.public_key
  let key3_public = key3.public_key
  let key4_public = key4.public_key
  let key5_public = key5.public_key
  let placeholder_epoch = case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  Ok(GeneratedTreeKemPath {
    key_material : TreeKemKeyMaterial {
      sender_chains : group_empty_keys() ?,
      skipped_keys : group_empty_keys() ?,
      epoch_secret : placeholder_epoch,
      leaf_private_key : leaf.private_key,
      level0_private_key : key0.private_key,
      level1_private_key : key1.private_key,
      level2_private_key : key2.private_key,
      level3_private_key : key3.private_key,
      level4_private_key : key4.private_key,
      level5_private_key : key5.private_key,
      available_levels : [0, 1, 2, 3, 4, 5]
    },
    secret0 : secret0,
    secret1 : secret1,
    secret2 : secret2,
    secret3 : secret3,
    secret4 : secret4,
    secret5 : secret5,
    leaf_public_key : leaf_public_key,
    parents : [TreeKemParentNode {
      node_index : List.get(path, 0),
      public_key : key0_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 1),
      public_key : key1_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 2),
      public_key : key2_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 3),
      public_key : key3_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 4),
      public_key : key4_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 5),
      public_key : key5_public,
      unmerged_leaves : List.new()
    }]
  })
end

fn seal_path_secret(secret :: borrow SecretBytes,
level :: Int,
recipient_public_key :: X25519PublicKey,
context :: Bytes,
recipient_node :: Int) -> Bytes ! GroupError do
  case Crypto.hpke_seal_secret(recipient_public_key,
  group_hpke_info(),
  group_path_aad(context, level, recipient_node) ?,
  secret) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( sealed) -> Ok(sealed)
  end
end

pub fn group_seal_generated_secret(value :: borrow GeneratedTreeKemPath,
level :: Int,
recipient_public_key :: X25519PublicKey,
context :: Bytes,
recipient_node :: Int) -> Bytes ! GroupError do
  if level == 0 do
    seal_path_secret(value.secret0, level, recipient_public_key, context, recipient_node)
  else if level == 1 do
    seal_path_secret(value.secret1, level, recipient_public_key, context, recipient_node)
  else if level == 2 do
    seal_path_secret(value.secret2, level, recipient_public_key, context, recipient_node)
  else if level == 3 do
    seal_path_secret(value.secret3, level, recipient_public_key, context, recipient_node)
  else if level == 4 do
    seal_path_secret(value.secret4, level, recipient_public_key, context, recipient_node)
  else if level == 5 do
    seal_path_secret(value.secret5, level, recipient_public_key, context, recipient_node)
  else
    Err(InvalidGroup)
  end
end

fn seal_resolution(values :: List < TreeKemResolutionNode >,
index :: Int,
excluded_leaf :: Int,
generated :: borrow GeneratedTreeKemPath,
level :: Int,
context :: Bytes,
output :: List < TreeKemCiphertext >) -> List < TreeKemCiphertext > ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    if value.node_index == 63 + excluded_leaf do
      seal_resolution(values, index + 1, excluded_leaf, generated, level, context, output)
    else
      let sealed = group_seal_generated_secret(generated,
      level,
      value.public_key,
      context,
      value.node_index) ?
      seal_resolution(values,
      index + 1,
      excluded_leaf,
      generated,
      level,
      context,
      List.append(output,
      TreeKemCiphertext {
        recipient_node : value.node_index,
        sealed : sealed
      }))
    end
  end
end

pub fn group_seal_update_nodes(tree :: borrow GroupTree,
committer_leaf :: Int,
generated :: borrow GeneratedTreeKemPath,
excluded_leaf :: Int,
context :: Bytes,
level :: Int,
output :: List < TreeKemUpdateNode >) -> List < TreeKemUpdateNode > ! GroupError do
  if level >= 6 do
    Ok(output)
  else
    let copath_nodes = group_tree_path_error(copath(committer_leaf)) ?
    let recipients = group_tree_resolution_error(resolution(tree, List.get(copath_nodes, level))) ?
    let ciphertexts = seal_resolution(recipients,
    0,
    excluded_leaf,
    generated,
    level,
    context,
    List.new()) ?
    group_seal_update_nodes(tree,
    committer_leaf,
    generated,
    excluded_leaf,
    context,
    level + 1,
    List.append(output,
    TreeKemUpdateNode {
      parent : List.get(generated.parents, level),
      ciphertexts : ciphertexts
    }))
  end
end

pub fn group_next_epoch_secret(root :: borrow SecretBytes, context :: Bytes) -> SecretBytes ! GroupError do
  case Crypto.hkdf_sha256(root, Crypto.sha256(context), Bytes.from_utf8("mesh-mls/v1/epoch"), 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

pub fn group_finish_generated(value :: consume GeneratedTreeKemPath, epoch_secret :: SecretBytes) -> TreeKemKeyMaterial do
  let key_material = value.key_material
  % { key_material | epoch_secret : epoch_secret }
end

fn has_level(values :: List < Int >, level :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if List.get(values, index) == level do
    true
  else
    has_level(values, level, index + 1)
  end
end

fn private_level_for_node(path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
node_index :: Int,
index :: Int) -> Int ! GroupError do
  if node_index == 63 + local_leaf do
    Ok(-1)
  else
    let nodes = group_tree_path_error(direct_path(local_leaf)) ?
    if index >= List.length(nodes) do
      Ok(-2)
    else if List.get(nodes, index) == node_index && has_level(path.available_levels, index, 0) do
      Ok(index)
    else
      private_level_for_node(path, local_leaf, node_index, index + 1)
    end
  end
end

fn open_with_private(path :: borrow TreeKemKeyMaterial,
private_level :: Int,
update_level :: Int,
context :: Bytes,
recipient_node :: Int,
sealed :: Bytes) -> SecretBytes ! GroupError do
  if private_level == -1 do
    case Crypto.hpke_open_secret(path.leaf_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 0 do
    case Crypto.hpke_open_secret(path.level0_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 1 do
    case Crypto.hpke_open_secret(path.level1_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 2 do
    case Crypto.hpke_open_secret(path.level2_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 3 do
    case Crypto.hpke_open_secret(path.level3_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 4 do
    case Crypto.hpke_open_secret(path.level4_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 5 do
    case Crypto.hpke_open_secret(path.level5_private_key,
    group_hpke_info(),
    group_path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else
    Err(RemovedMember)
  end
end

fn open_level_ciphertexts(values :: List < TreeKemCiphertext >,
index :: Int,
path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
update_level :: Int,
context :: Bytes) -> OpenedPathSecret ! GroupError do
  if index >= List.length(values) do
    Err(RemovedMember)
  else
    let value = List.get(values, index)
    let private_level = private_level_for_node(path, local_leaf, value.recipient_node, 0) ?
    if private_level < -1 do
      open_level_ciphertexts(values, index + 1, path, local_leaf, update_level, context)
    else
      Ok(OpenedPathSecret {
        secret : open_with_private(path,
        private_level,
        update_level,
        context,
        value.recipient_node,
        value.sealed) ?,
        level : update_level
      })
    end
  end
end

pub fn group_open_update_path(values :: List < TreeKemUpdateNode >,
level :: Int,
path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
context :: Bytes) -> OpenedPathSecret ! GroupError do
  if level >= List.length(values) do
    Err(RemovedMember)
  else
    case open_level_ciphertexts(List.get(values, level).ciphertexts,
    0,
    path,
    local_leaf,
    level,
    context) do
      Err( RemovedMember) -> group_open_update_path(values, level + 1, path, local_leaf, context)
      Err( error) -> Err(error)
      Ok( opened) -> Ok(opened)
    end
  end
end

fn expected_recipient_nodes(values :: List < TreeKemResolutionNode >,
index :: Int,
excluded_leaf :: Int,
output :: List < Int >) -> List < Int > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.node_index == 63 + excluded_leaf do
      expected_recipient_nodes(values, index + 1, excluded_leaf, output)
    else
      expected_recipient_nodes(values,
      index + 1,
      excluded_leaf,
      List.append(output, value.node_index))
    end
  end
end

fn validate_ciphertext_recipients(values :: List < TreeKemCiphertext >,
expected :: List < Int >,
index :: Int) -> Result <(), GroupError > do
  if List.length(values) != List.length(expected) do
    Err(AuthenticationRejected)
  else if index >= List.length(values) do
    Ok(nil)
  else if List.get(values, index).recipient_node != List.get(expected, index) do
    Err(AuthenticationRejected)
  else
    validate_ciphertext_recipients(values, expected, index + 1)
  end
end

pub fn group_validate_update_recipients(tree :: borrow GroupTree,
committer_leaf :: Int,
update_path :: TreeKemUpdatePath,
excluded_leaf :: Int,
level :: Int) -> Result <(), GroupError > do
  if level >= 6 do
    Ok(nil)
  else
    let copath_nodes = group_tree_path_error(copath(committer_leaf)) ?
    let recipients = group_tree_resolution_error(resolution(tree, List.get(copath_nodes, level))) ?
    let expected = expected_recipient_nodes(recipients, 0, excluded_leaf, List.new())
    validate_ciphertext_recipients(List.get(update_path.nodes, level).ciphertexts, expected, 0) ?
    group_validate_update_recipients(tree, committer_leaf, update_path, excluded_leaf, level + 1)
  end
end

fn dummy_private() -> X25519PrivateKey ! GroupError do
  Ok((fresh_x25519() ?).private_key)
end

fn build_patch0(secret0 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret1 = derive_path_secret(secret0) ?
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key0 = derive_node_key(secret0, List.get(nodes, 0).parent.node_index) ?
  let key1 = derive_node_key(secret1, List.get(nodes, 1).parent.node_index) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret0)
  Secret.destroy(secret1)
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key0.public_key.bytes, List.get(nodes, 0).parent.public_key.bytes) || !Bytes.secure_equals(key1.public_key.bytes,
  List.get(nodes, 1).parent.public_key.bytes) || !Bytes.secure_equals(key2.public_key.bytes,
  List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch0(epoch_secret,
    key0.private_key,
    key1.private_key,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch1(secret1 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key1 = derive_node_key(secret1, List.get(nodes, 1).parent.node_index) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret1)
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key1.public_key.bytes, List.get(nodes, 1).parent.public_key.bytes) || !Bytes.secure_equals(key2.public_key.bytes,
  List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch1(epoch_secret,
    key1.private_key,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch2(secret2 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key2.public_key.bytes, List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch2(epoch_secret,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch3(secret3 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key3.public_key.bytes, List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch3(epoch_secret, key3.private_key, key4.private_key, key5.private_key))
  end
end

fn build_patch4(secret4 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret5 = derive_path_secret(secret4) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key4.public_key.bytes, List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch4(epoch_secret, key4.private_key, key5.private_key))
  end
end

fn build_patch5(secret5 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = group_next_epoch_secret(secret5, context) ?
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key5.public_key.bytes, List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch5(epoch_secret, key5.private_key))
  end
end

pub fn group_derive_verified_patch(secret :: SecretBytes,
start_level :: Int,
nodes :: List < TreeKemUpdateNode >,
context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let patch = if start_level == 0 do
    build_patch0(secret, nodes, context) ?
  else if start_level == 1 do
    build_patch1(secret, nodes, context) ?
  else if start_level == 2 do
    build_patch2(secret, nodes, context) ?
  else if start_level == 3 do
    build_patch3(secret, nodes, context) ?
  else if start_level == 4 do
    build_patch4(secret, nodes, context) ?
  else if start_level == 5 do
    build_patch5(secret, nodes, context) ?
  else
    Err(InvalidGroup) ?
  end
  Ok(patch)
end

fn preserved_levels(values :: List < Int >,
start_level :: Int,
index :: Int,
output :: List < Int >) -> List < Int > do
  if index >= List.length(values) do
    output
  else
    let level = List.get(values, index)
    if level < start_level do
      preserved_levels(values, start_level, index + 1, List.append(output, level))
    else
      preserved_levels(values, start_level, index + 1, output)
    end
  end
end

fn append_levels(start_level :: Int, output :: List < Int >) -> List < Int > do
  if start_level >= 6 do
    output
  else
    append_levels(start_level + 1, List.append(output, start_level))
  end
end

pub fn group_merge_key_material(base :: consume TreeKemKeyMaterial,
patch :: consume TreeKemPathPatch) -> TreeKemKeyMaterial do
  case patch do
    TreeKemPatch0( epoch_secret, level0, level1, level2, level3, level4, level5) -> % { base | epoch_secret : epoch_secret, level0_private_key : level0, level1_private_key : level1, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : [0, 1, 2, 3, 4, 5] }
    TreeKemPatch1( epoch_secret, level1, level2, level3, level4, level5) -> do
      let levels = append_levels(1, preserved_levels(base.available_levels, 1, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level1_private_key : level1, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch2( epoch_secret, level2, level3, level4, level5) -> do
      let levels = append_levels(2, preserved_levels(base.available_levels, 2, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch3( epoch_secret, level3, level4, level5) -> do
      let levels = append_levels(3, preserved_levels(base.available_levels, 3, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch4( epoch_secret, level4, level5) -> do
      let levels = append_levels(4, preserved_levels(base.available_levels, 4, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch5( epoch_secret, level5) -> do
      let levels = append_levels(5, preserved_levels(base.available_levels, 5, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level5_private_key : level5, available_levels : levels }
    end
  end
end

pub fn group_empty_keys() -> SecretMap ! GroupError do
  case SecretMap.new(64) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

pub fn group_derive_secret(secret :: borrow SecretBytes, salt :: Bytes, label :: Bytes) -> SecretBytes ! GroupError do
  case Crypto.hkdf_sha256(secret, salt, label, 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

pub fn group_mix_epoch(secret :: SecretBytes, previous :: borrow SecretBytes, context :: Bytes) -> SecretBytes ! GroupError do
  let prior = group_derive_secret(previous,
  Crypto.sha256(context),
  Bytes.from_utf8("mesh-mls/v2/epoch-mix")) ?
  let combined = case Secret.concat(prior, secret) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  group_derive_secret(combined, Crypto.sha256(context), Bytes.from_utf8("mesh-mls/v2/epoch"))
end

pub fn group_confirmation(secret :: borrow SecretBytes, context :: Bytes) -> Bytes ! GroupError do
  let material = group_derive_secret(secret,
  Crypto.sha256(context),
  Bytes.from_utf8("mesh-mls/v2/confirmation")) ?
  let key = case Crypto.aead_key(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  case Crypto.aead_seal(key,
  group_join([group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?],
  0,
  Bytes.empty()) ?,
  context,
  Bytes.empty()) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( tag) -> Ok(tag)
  end
end

pub fn group_verify_confirmation(secret :: borrow SecretBytes, context :: Bytes, tag :: Bytes) -> Result <(), GroupError > do
  let material = group_derive_secret(secret,
  Crypto.sha256(context),
  Bytes.from_utf8("mesh-mls/v2/confirmation")) ?
  let key = case Crypto.aead_key(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  case Crypto.aead_open(key,
  group_join([group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?, group_byte(0) ?],
  0,
  Bytes.empty()) ?,
  context,
  tag) do
    Err( _) -> Err(AuthenticationRejected)
    Ok( value) -> if Bytes.length(value) == 0 do
      Ok(nil)
    else
      Err(AuthenticationRejected)
    end
  end
end

pub fn group_chain_id(leaf :: Int) -> Bytes ! GroupError do
  group_write_u16(leaf)
end

fn initialize_sender_chains(secret :: borrow SecretBytes,
group_id :: Bytes,
tree :: borrow GroupTree,
chains :: borrow SecretMap,
leaf :: Int) -> Result <(), GroupError > do
  if leaf >= 64 do
    Ok(nil)
  else
    case member_at(tree, leaf) do
      Err( _) -> initialize_sender_chains(secret, group_id, tree, chains, leaf + 1)
      Ok( _) -> do
        let id = group_chain_id(leaf) ?
        let label = group_append(Bytes.from_utf8("mesh-mls/v2/sender-chain"), id) ?
        let chain = group_derive_secret(secret, group_id, label) ?
        case SecretMap.insert(chains, id, chain) do
          Err( error) -> Err(CryptoFailure(error))
          Ok( _) -> initialize_sender_chains(secret, group_id, tree, chains, leaf + 1)
        end
      end
    end
  end
end

# No application ancestor survives this split. Tree/HPKE keys alone cannot undo the previous-init mix.

pub fn group_epoch_keys(secret :: borrow SecretBytes, group_id :: Bytes, tree :: borrow GroupTree) -> GroupEpochKeys ! GroupError do
  let chains = group_empty_keys() ?
  let skipped = group_empty_keys() ?
  initialize_sender_chains(secret, group_id, tree, chains, 0) ?
  let next_init = group_derive_secret(secret, group_id, Bytes.from_utf8("mesh-mls/v2/next-init")) ?
  Ok(EpochKeys(next_init, chains, skipped))
end

pub fn group_install_epoch(material :: consume TreeKemKeyMaterial, keys :: consume GroupEpochKeys) -> TreeKemKeyMaterial do
  case keys do
    EpochKeys( init_secret, chains, skipped) -> % { material | epoch_secret : init_secret, sender_chains : chains, skipped_keys : skipped }
  end
end

pub fn group_initialize_epoch(material :: consume TreeKemKeyMaterial,
group_id :: Bytes,
tree :: borrow GroupTree) -> TreeKemKeyMaterial ! GroupError do
  let keys = group_epoch_keys(material.epoch_secret, group_id, tree) ?
  Ok(group_install_epoch(material, keys))
end

pub fn group_prepare_patch(patch :: consume TreeKemPathPatch,
previous :: borrow SecretBytes,
group_id :: Bytes,
tree :: borrow GroupTree,
context :: Bytes,
confirmation :: Bytes) -> Result <( TreeKemPathPatch, GroupEpochKeys), GroupError > do
  case patch do
    TreeKemPatch0( root, key0, key1, key2, key3, key4, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch0(secret, key0, key1, key2, key3, key4, key5), keys))
    end
    TreeKemPatch1( root, key1, key2, key3, key4, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch1(secret, key1, key2, key3, key4, key5), keys))
    end
    TreeKemPatch2( root, key2, key3, key4, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch2(secret, key2, key3, key4, key5), keys))
    end
    TreeKemPatch3( root, key3, key4, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch3(secret, key3, key4, key5), keys))
    end
    TreeKemPatch4( root, key4, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch4(secret, key4, key5), keys))
    end
    TreeKemPatch5( root, key5) -> do
      let secret = group_mix_epoch(root, previous, context) ?
      group_verify_confirmation(secret, context, confirmation) ?
      let keys = group_epoch_keys(secret, group_id, tree) ?
      Ok((TreeKemPatch5(secret, key5), keys))
    end
  end
end
