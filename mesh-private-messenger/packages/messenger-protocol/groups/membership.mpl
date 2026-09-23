from Groups.Mls import invalid_group_member_error

##! Groups.Membership for the bounded messenger group protocol.

from Groups.CommitWire import (
  group_commit_unsigned,
  group_extensions_bytes,
  group_policy_bytes,
  group_signed_commit_bytes,
  group_update_path_context,
  group_validate_commit_shape
)
from Groups.GroupCodec import (
  group_join,
  group_next_epoch,
  group_tree_error,
  group_tree_member_error,
  group_valid_extensions,
  group_validate_member_policy,
  group_validate_members,
  group_validate_policy,
  group_zero
)
from Groups.KeySchedule import (
  group_base_key_material,
  group_confirmation,
  group_mix_epoch,
  group_initialize_epoch,
  group_epoch_keys,
  group_install_epoch,
  group_prepare_patch,
  group_verify_confirmation,
  group_derive_verified_patch,
  group_destroy_private,
  group_finish_generated,
  group_generate_treekem_path,
  group_hpke_info,
  group_merge_key_material,
  group_next_epoch_secret,
  group_open_update_path,
  group_path_aad,
  group_seal_generated_secret,
  group_seal_update_nodes,
  group_validate_update_recipients,
  group_welcome_context
)
from Groups.Mls import (
  CommitApplyOutcome,
  GeneratedTreeKemPath,
  GroupAddOutcome,
  GroupCommit,
  GroupError,
  GroupEpochKeys,
  GroupProposal,
  GroupRemoveOutcome,
  GroupState,
  GroupTransparencyPolicy,
  GroupWelcome,
  OpenedPathSecret,
  PreparedAppliedCommit,
  PreparedGroupAdd,
  PreparedGroupRemove,
  PreparedJoin,
  TreeKemKeyMaterial,
  TreeKemPathPatch,
  TreeKemUpdateNode,
  TreeKemUpdatePath
)
from Groups.Tree import (
  GroupMember,
  GroupTree,
  GroupTreeError,
  IndexedGroupMember,
  TreeKemParentNode,
  apply_update_path,
  empty_tree,
  indexed_members,
  insert_member,
  member_at,
  public_parent_nodes,
  remove_member,
  tree_from_public,
  tree_hash,
  update_leaf_public_key
)
from Groups.WelcomeWire import (
  group_joiner_level,
  group_public_update_nodes,
  group_update_parents,
  group_validate_welcome_shape
)

fn apply_proposal(tree :: GroupTree, proposal :: GroupProposal) -> GroupTree!GroupError do
  case proposal do
    UpdateKeys -> Ok(tree)
    AddMember(leaf_index, member) -> case insert_member(tree, member) do
      Err(error) -> Err(TreeFailure(error))
      Ok(value) -> do
        let (next, actual_leaf) = value
        if actual_leaf == leaf_index do
          Ok(next)
        else
          Err(InvalidGroup)
        end
      end
    end
    RemoveMember(leaf_index) -> case remove_member(tree, leaf_index) do
      Err(error) -> Err(TreeFailure(error))
      Ok(next)
    end
  end
end

fn verify_commit(value :: GroupCommit, prior_tree :: GroupTree) -> Result<(), GroupError> do
  let committer = case member_at(prior_tree, value.committer_leaf) do
    Err(error) -> Err(TreeFailure(error))
    Ok(member)
  end?
  let valid = case Crypto.verify(committer.signing_public_key,
    group_commit_unsigned(value)?,
    value.signature) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(result)
  end?
  if valid do
    Ok(nil)
  else
    Err(AuthenticationRejected)
  end
end

fn initial_transcript(group_id :: Bytes,
  tree :: GroupTree,
  extensions :: List<Int>,
  policy :: GroupTransparencyPolicy) -> Bytes!GroupError do
  Ok(Crypto.sha256(group_join([
      Bytes.from_utf8("mesh-mls/v1/group"),
      group_id,
      tree_hash(tree),
      group_extensions_bytes(extensions)?,
      group_policy_bytes(policy)?
    ],
    0,
    Bytes.empty())?))
end

pub fn create_group(creator :: GroupMember,
  leaf_private_key :: consume X25519PrivateKey,
  extensions :: List<Int>,
  policy :: GroupTransparencyPolicy) -> GroupState!GroupError do
  if !group_valid_extensions(extensions, 0, 0) do
    group_destroy_private(leaf_private_key)
    Err(InvalidGroup)
  else
    case group_validate_member_policy(creator, extensions, policy) do
      Err(error) -> do
        group_destroy_private(leaf_private_key)
        Err(error)
      end
      Ok(_) -> case Crypto.x25519_public(leaf_private_key) do
        Err(error) -> do
          group_destroy_private(leaf_private_key)
          Err(CryptoFailure(error))
        end
        Ok(public_key) -> if !Bytes.secure_equals(public_key.bytes, creator.leaf_public_key.bytes) do
          group_destroy_private(leaf_private_key)
          Err(AuthenticationRejected)
        else
          let group_id = case Crypto.random_bytes(32) do
            Err(error) -> Err(CryptoFailure(error))
            Ok(value)
          end?
          let secret = case Secret.random(32) do
            Err(error) -> Err(CryptoFailure(error))
            Ok(value)
          end?
          let inserted = case insert_member(case empty_tree() do
              Err(error) -> Err(TreeFailure(error))
              Ok(value)
            end?,
            creator) do
            Err(error) -> Err(TreeFailure(error))
            Ok(value)
          end?
          let (tree, creator_leaf) = inserted
          if creator_leaf != 0 do
            group_destroy_private(leaf_private_key)
            Secret.destroy(secret)
            Err(InvalidGroup)
          else
            Ok(GroupState {
              version: 2,
              suite: 3,
              group_id: group_id,
              epoch: group_zero()?,
              tree: tree,
              tree_hash_cache: tree_hash(tree),
              transcript_hash: initial_transcript(group_id, tree, extensions, policy)?,
              key_material: group_initialize_epoch(group_base_key_material(secret, leaf_private_key)?,
                group_id,
                tree)?,
              local_leaf: 0,
              next_generation: 0,
              received_generations: List.new(),
              extensions: extensions,
              policy: policy,
              snapshot_version: group_zero()?
            })
          end
        end
      end
    end
  end
end

fn prepare_add(state :: borrow GroupState,
  signing_key :: borrow SigningPrivateKey,
  member :: GroupMember) -> PreparedGroupAdd!GroupError do
  group_validate_member_policy(member, state.extensions, state.policy)?
  let inserted = case insert_member(state.tree, member) do
    Err(error) -> Err(TreeFailure(error))
    Ok(value)
  end?
  let (proposal_tree, recipient_leaf) = inserted
  let epoch = group_next_epoch(state.epoch)?
  let proposal = AddMember(recipient_leaf, member)
  let generated = group_generate_treekem_path(state.local_leaf)?
  let public_path = TreeKemUpdatePath {
    leaf_public_key: generated.leaf_public_key,
    nodes: group_public_update_nodes(generated.parents, 0, List.new())
  }
  let leaf_tree = group_tree_error(update_leaf_public_key(proposal_tree,
    state.local_leaf,
    generated.leaf_public_key))?
  let next_tree = group_tree_error(apply_update_path(leaf_tree, state.local_leaf, generated.parents))?
  let context = group_update_path_context(2,
    3,
    state.group_id,
    state.epoch,
    epoch,
    state.local_leaf,
    state.transcript_hash,
    tree_hash(next_tree),
    proposal,
    public_path)?
  let update_path = TreeKemUpdatePath {
    leaf_public_key: generated.leaf_public_key,
    nodes: group_seal_update_nodes(proposal_tree,
      state.local_leaf,
      generated,
      recipient_leaf,
      context,
      0,
      List.new())?
  }
  let secret = group_mix_epoch(group_next_epoch_secret(generated.secret5, context)?,
    state.key_material.epoch_secret,
    context)?
  let unsigned = GroupCommit {
    version: 2,
    suite: 3,
    group_id: state.group_id,
    prior_epoch: state.epoch,
    epoch: epoch,
    committer_leaf: state.local_leaf,
    prior_transcript_hash: state.transcript_hash,
    tree_hash: tree_hash(next_tree),
    proposal: proposal,
    update_path: update_path,
    confirmation: group_confirmation(secret, context)?,
    signature: Signature { bytes: Bytes.empty() }
  }
  let signature = case Crypto.sign(signing_key, group_commit_unsigned(unsigned)?) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  let commit = % { unsigned | signature: signature }
  verify_commit(commit, state.tree)?
  let transcript_hash = Crypto.sha256(group_signed_commit_bytes(commit)?)
  let level = group_joiner_level(state.local_leaf, recipient_leaf, 0)?
  let join_context = group_welcome_context(context, state.extensions, state.policy)?
  let joiner_secret = group_seal_generated_secret(generated,
    level,
    member.init_public_key,
    join_context,
    63 + recipient_leaf)?
  let welcome = GroupWelcome {
    commit: commit,
    members: indexed_members(next_tree),
    extensions: state.extensions,
    policy: state.policy,
    recipient_leaf: recipient_leaf,
    parent_nodes: public_parent_nodes(next_tree),
    joiner_path_level: level,
    joiner_path_secret: joiner_secret,
    joiner_epoch_secret: case Crypto.hpke_seal_secret(member.init_public_key,
      Bytes.from_utf8("mesh-mls/v2/welcome-epoch"),
      group_signed_commit_bytes(commit)?,
      secret) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(value)
    end?
  }
  Ok(PreparedGroupAdd {
    tree: next_tree,
    key_material: group_initialize_epoch(group_finish_generated(generated, secret),
      state.group_id,
      next_tree)?,
    commit: commit,
    welcome: welcome,
    transcript_hash: transcript_hash
  })
end

pub fn commit_add(state :: consume GroupState,
  signing_key :: borrow SigningPrivateKey,
  member :: GroupMember) -> GroupAddOutcome do
  case prepare_add(state, signing_key, member) do
    Err(error) -> GroupAddRejected(state, error)
    Ok(prepared) -> do
      let tree = prepared.tree
      let commit = prepared.commit
      let welcome = prepared.welcome
      let transcript_hash = prepared.transcript_hash
      let next = % { state | version: 2, epoch: commit.epoch, tree: tree, tree_hash_cache: tree_hash(tree), transcript_hash: transcript_hash, key_material: prepared.key_material, next_generation: 0, received_generations: List.new() }
      GroupMemberAdded(next, commit, welcome)
    end
  end
end

fn prepare_remove(state :: borrow GroupState,
  signing_key :: borrow SigningPrivateKey,
  leaf_index :: Int) -> PreparedGroupRemove!GroupError do
  if leaf_index == state.local_leaf do
    Err(invalid_group_member_error())
  else
    let proposal_tree = if leaf_index == -1 do
      Ok(state.tree)
    else
      case remove_member(state.tree, leaf_index) do
        Err(error) -> Err(TreeFailure(error))
        Ok(value)
      end
    end?
    let epoch = group_next_epoch(state.epoch)?
    let proposal = if leaf_index == -1 do
      UpdateKeys
    else
      RemoveMember(leaf_index)
    end
    let generated = group_generate_treekem_path(state.local_leaf)?
    let public_path = TreeKemUpdatePath {
      leaf_public_key: generated.leaf_public_key,
      nodes: group_public_update_nodes(generated.parents, 0, List.new())
    }
    let leaf_tree = group_tree_error(update_leaf_public_key(proposal_tree,
      state.local_leaf,
      generated.leaf_public_key))?
    let next_tree = group_tree_error(apply_update_path(leaf_tree,
      state.local_leaf,
      generated.parents))?
    let context = group_update_path_context(2,
      3,
      state.group_id,
      state.epoch,
      epoch,
      state.local_leaf,
      state.transcript_hash,
      tree_hash(next_tree),
      proposal,
      public_path)?
    let update_path = TreeKemUpdatePath {
      leaf_public_key: generated.leaf_public_key,
      nodes: group_seal_update_nodes(proposal_tree,
        state.local_leaf,
        generated,
        -1,
        context,
        0,
        List.new())?
    }
    let secret = group_mix_epoch(group_next_epoch_secret(generated.secret5, context)?,
      state.key_material.epoch_secret,
      context)?
    let unsigned = GroupCommit {
      version: 2,
      suite: 3,
      group_id: state.group_id,
      prior_epoch: state.epoch,
      epoch: epoch,
      committer_leaf: state.local_leaf,
      prior_transcript_hash: state.transcript_hash,
      tree_hash: tree_hash(next_tree),
      proposal: proposal,
      update_path: update_path,
      confirmation: group_confirmation(secret, context)?,
      signature: Signature { bytes: Bytes.empty() }
    }
    let signature = case Crypto.sign(signing_key, group_commit_unsigned(unsigned)?) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(value)
    end?
    let commit = % { unsigned | signature: signature }
    verify_commit(commit, state.tree)?
    let transcript_hash = Crypto.sha256(group_signed_commit_bytes(commit)?)
    Ok(PreparedGroupRemove {
      tree: next_tree,
      key_material: group_initialize_epoch(group_finish_generated(generated, secret),
        state.group_id,
        next_tree)?,
      commit: commit,
      transcript_hash: transcript_hash
    })
  end
end

pub fn commit_remove(state :: consume GroupState,
  signing_key :: borrow SigningPrivateKey,
  leaf_index :: Int) -> GroupRemoveOutcome do
  case prepare_remove(state, signing_key, leaf_index) do
    Err(error) -> GroupRemoveRejected(state, error)
    Ok(prepared) -> do
      let tree = prepared.tree
      let commit = prepared.commit
      let transcript_hash = prepared.transcript_hash
      let next = % { state | version: 2, epoch: commit.epoch, tree: tree, tree_hash_cache: tree_hash(tree), transcript_hash: transcript_hash, key_material: prepared.key_material, next_generation: 0, received_generations: List.new() }
      GroupMemberRemoved(next, commit)
    end
  end
end

fn transition_tree(prior_tree :: GroupTree, commit :: GroupCommit) -> GroupTree!GroupError do
  let proposal_tree = apply_proposal(prior_tree, commit.proposal)?
  let excluded = case commit.proposal do
    AddMember(leaf, _) -> leaf
    RemoveMember(_) -> -1
    UpdateKeys -> -1
  end
  group_validate_update_recipients(proposal_tree,
    commit.committer_leaf,
    commit.update_path,
    excluded,
    0)?
  let leaf_tree = group_tree_error(update_leaf_public_key(proposal_tree,
    commit.committer_leaf,
    commit.update_path.leaf_public_key))?
  let next_tree = group_tree_error(apply_update_path(leaf_tree,
    commit.committer_leaf,
    group_update_parents(commit.update_path.nodes, 0, List.new())))?
  if Bytes.secure_equals(tree_hash(next_tree), commit.tree_hash) do
    Ok(next_tree)
  else
    Err(AuthenticationRejected)
  end
end

fn prepare_join(welcome :: GroupWelcome,
  init_private_key :: borrow X25519PrivateKey,
  leaf_public_key :: X25519PublicKey) -> PreparedJoin!GroupError do
  group_validate_welcome_shape(welcome)?
  if (welcome.commit.version != 1 && welcome.commit.version != 2) || welcome.commit.suite != 3 || Bytes.length(welcome.commit.group_id) != 32 || !group_valid_extensions(welcome.extensions,
    0,
    0) do
    Err(InvalidGroup)
  else
    group_validate_policy(welcome.policy)?
    group_validate_members(welcome.members, welcome.extensions, welcome.policy, 0)?
    let tree = group_tree_error(tree_from_public(welcome.members, welcome.parent_nodes))?
    verify_commit(welcome.commit, tree)?
    if !Bytes.secure_equals(tree_hash(tree), welcome.commit.tree_hash) do
      Err(AuthenticationRejected)
    else
      let init_public_key = case Crypto.x25519_public(init_private_key) do
        Err(error) -> Err(CryptoFailure(error))
        Ok(value)
      end?
      let recipient = group_tree_member_error(member_at(tree, welcome.recipient_leaf))?
      if !Bytes.secure_equals(recipient.init_public_key.bytes, init_public_key.bytes) || !Bytes.secure_equals(recipient.leaf_public_key.bytes,
        leaf_public_key.bytes) do
        Err(AuthenticationRejected)
      else
        let context = group_update_path_context(welcome.commit.version,
          welcome.commit.suite,
          welcome.commit.group_id,
          welcome.commit.prior_epoch,
          welcome.commit.epoch,
          welcome.commit.committer_leaf,
          welcome.commit.prior_transcript_hash,
          welcome.commit.tree_hash,
          welcome.commit.proposal,
          welcome.commit.update_path)?
        let path_secret = case Crypto.hpke_open_secret(init_private_key,
          group_hpke_info(),
          group_path_aad(group_welcome_context(context, welcome.extensions, welcome.policy)?,
            welcome.joiner_path_level,
            63 + welcome.recipient_leaf)?,
          welcome.joiner_path_secret) do
          Err(error) -> Err(CryptoFailure(error))
          Ok(value)
        end?
        Ok(PreparedJoin {
          tree: tree,
          path_secret: path_secret,
          path_level: welcome.joiner_path_level,
          context: context
        })
      end
    end
  end
end

pub fn join_from_welcome(welcome :: GroupWelcome,
  init_private_key :: borrow X25519PrivateKey,
  leaf_private_key :: consume X25519PrivateKey) -> GroupState!GroupError do
  case Crypto.x25519_public(leaf_private_key) do
    Err(error) -> do
      group_destroy_private(leaf_private_key)
      Err(CryptoFailure(error))
    end
    Ok(leaf_public_key) -> do
      case prepare_join(welcome, init_private_key, leaf_public_key) do
        Err(error) -> do
          group_destroy_private(leaf_private_key)
          Err(error)
        end
        Ok(prepared) -> do
          let tree = prepared.tree
          let path_level = prepared.path_level
          let context = prepared.context
          let placeholder_epoch = case Secret.random(32) do
            Err(error) -> Err(CryptoFailure(error))
            Ok(value)
          end?
          let base = group_base_key_material(placeholder_epoch, leaf_private_key)?
          let patch = group_derive_verified_patch(prepared.path_secret,
            path_level,
            welcome.commit.update_path.nodes,
            context)?
          let material = group_merge_key_material(base, patch)
          let material = if welcome.commit.version == 2 do
            let seed = case Crypto.hpke_open_secret(init_private_key,
              Bytes.from_utf8("mesh-mls/v2/welcome-epoch"),
              group_signed_commit_bytes(welcome.commit)?,
              welcome.joiner_epoch_secret) do
              Err(error) -> Err(CryptoFailure(error))
              Ok(value)
            end?
            group_verify_confirmation(seed, context, welcome.commit.confirmation)?
            let keys = group_epoch_keys(seed, welcome.commit.group_id, tree)?
            group_install_epoch(material, keys)
          else
            material
          end
          Ok(GroupState {
            version: welcome.commit.version,
            suite: 3,
            group_id: welcome.commit.group_id,
            epoch: welcome.commit.epoch,
            tree: tree,
            tree_hash_cache: welcome.commit.tree_hash,
            transcript_hash: Crypto.sha256(group_signed_commit_bytes(welcome.commit)?),
            key_material: material,
            local_leaf: welcome.recipient_leaf,
            next_generation: 0,
            received_generations: List.new(),
            extensions: welcome.extensions,
            policy: welcome.policy,
            snapshot_version: group_zero()?
          })
        end
      end
    end
  end
end

fn apply_verified_commit(state :: borrow GroupState, commit :: GroupCommit) -> PreparedAppliedCommit!GroupError do
  group_validate_commit_shape(commit)?
  if (commit.version != 1 && commit.version != 2) || commit.version < state.version || commit.suite != state.suite || !Bytes.secure_equals(commit.group_id,
    state.group_id) do
    Err(AuthenticationRejected)
  else if U64.compare(commit.prior_epoch, state.epoch) < 0 do
    Err(StaleEpoch)
  else if U64.compare(commit.prior_epoch, state.epoch) > 0 do
    Err(FutureEpoch)
  else if U64.compare(commit.epoch, group_next_epoch(state.epoch)?) != 0 do
    Err(FutureEpoch)
  else if !Bytes.secure_equals(commit.prior_transcript_hash, state.transcript_hash) do
    Err(AuthenticationRejected)
  else
    verify_commit(commit, state.tree)?
    let next_tree = transition_tree(state.tree, commit)?
    let next_members = indexed_members(next_tree)
    group_validate_members(next_members, state.extensions, state.policy, 0)?
    case member_at(next_tree, state.local_leaf) do
      Err(_) -> Err(RemovedMember)
      Ok(_) -> do
        let context = group_update_path_context(commit.version,
          commit.suite,
          commit.group_id,
          commit.prior_epoch,
          commit.epoch,
          commit.committer_leaf,
          commit.prior_transcript_hash,
          commit.tree_hash,
          commit.proposal,
          commit.update_path)?
        Ok(PreparedAppliedCommit {
          tree: next_tree,
          context: context
        })
      end
    end
  end
end

pub fn apply_commit(state :: consume GroupState, commit :: GroupCommit) -> CommitApplyOutcome do
  case apply_verified_commit(state, commit) do
    Err(error) -> CommitRejected(state, error)
    Ok(prepared) -> case group_signed_commit_bytes(commit) do
      Err(error) -> CommitRejected(state, error)
      Ok(signed) -> case group_open_update_path(commit.update_path.nodes,
        0,
        state.key_material,
        state.local_leaf,
        prepared.context) do
        Err(error) -> CommitRejected(state, error)
        Ok(opened) -> do
          let opened_level = opened.level
          case group_derive_verified_patch(opened.secret,
            opened_level,
            commit.update_path.nodes,
            prepared.context) do
            Err(error) -> CommitRejected(state, error)
            Ok(patch) -> apply_prepared_patch(state, commit, prepared, signed, patch)
          end
        end
      end
    end
  end
end

fn apply_prepared_patch(state :: consume GroupState,
  commit :: GroupCommit,
  prepared :: PreparedAppliedCommit,
  signed :: Bytes,
  patch :: consume TreeKemPathPatch) -> CommitApplyOutcome do
  if commit.version == 1 do
    finish_applied(state, commit, prepared, signed, patch, None)
  else
    case group_prepare_patch(patch,
      state.key_material.epoch_secret,
      state.group_id,
      prepared.tree,
      prepared.context,
      commit.confirmation) do
      Err(error) -> CommitRejected(state, error)
      Ok(value) -> do
        let (patch, keys) = value
        finish_applied(state, commit, prepared, signed, patch, Some(keys))
      end
    end
  end
end

fn finish_applied(state :: consume GroupState,
  commit :: GroupCommit,
  prepared :: PreparedAppliedCommit,
  signed :: Bytes,
  patch :: consume TreeKemPathPatch,
  keys :: Option<GroupEpochKeys>) -> CommitApplyOutcome do
  let suite = state.suite
  let group_id = state.group_id
  let local_leaf = state.local_leaf
  let extensions = state.extensions
  let policy = state.policy
  let snapshot_version = state.snapshot_version
  let material = group_merge_key_material(state.key_material, patch)
  let material = case keys do
    None -> material
    Some(value) -> group_install_epoch(material, value)
  end
  CommitApplied(GroupState {
    version: commit.version,
    suite: suite,
    group_id: group_id,
    epoch: commit.epoch,
    tree: prepared.tree,
    tree_hash_cache: commit.tree_hash,
    transcript_hash: Crypto.sha256(signed),
    key_material: material,
    local_leaf: local_leaf,
    next_generation: 0,
    received_generations: List.new(),
    extensions: extensions,
    policy: policy,
    snapshot_version: snapshot_version
  })
end

pub fn commit_update(state :: consume GroupState, signing_key :: borrow SigningPrivateKey) -> GroupRemoveOutcome do
  commit_remove(state, signing_key, -1)
end
