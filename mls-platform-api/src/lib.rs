mod state;

use mls_rs::error::{AnyError, IntoAnyError};
use mls_rs::group::proposal::{CustomProposal, ProposalType};
use mls_rs::group::{ExportedTree, ReceivedMessage};
use mls_rs::identity::{Credential, SigningIdentity};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{CipherSuiteProvider, CryptoProvider, Extension, ExtensionList, IdentityProvider};

use sha2::Sha256;
pub use state::{PlatformState, TemporaryState};

pub type DefaultCryptoProvider = mls_rs_crypto_rustcrypto::RustCryptoProvider;
pub type DefaultIdentityProvider = mls_rs::identity::basic::BasicIdentityProvider;

// Re-export the mls_rs types
pub use mls_rs::CipherSuite;
pub use mls_rs::MlsMessage;
pub use mls_rs::ProtocolVersion;

// Import some mls_rs types
use mls_rs::identity::basic::BasicCredential;

// Define new types
pub type GroupId = Vec<u8>;
pub type GroupState = Vec<u8>;
pub type Identity = Vec<u8>;
pub type GroupEpoch = u64;

#[allow(clippy::large_enum_variant)]
pub enum MlsMessageOrAck {
    Ack,
    MlsMessage(MlsMessage),
}

///
/// Errors
///
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error(transparent)]
    MlsError(#[from] mls_rs::error::MlsError),
    #[error("IdentityError")]
    IdentityError(AnyError),
    #[error("CryptoError")]
    CryptoError(AnyError),
    #[error("UnsupportedCiphersuite")]
    UnsupportedCiphersuite,
    #[error("UnsupportedGroupConfig")]
    UnsupportedGroupConfig,
    #[error("UndefinedSigningIdentity")]
    UndefinedSigningIdentity,
    #[error("StorageError")]
    StorageError(AnyError),
    #[error("UnavailableSecret")]
    UnavailableSecret,
    #[error("MutexError")]
    MutexError,
    #[error(transparent)]
    MlsCodecError(#[from] mls_rs::mls_rs_codec::Error),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

///
/// Generate or Retrieve a PlatformState.
///
pub fn state_access(db_path: String, db_key: [u8; 32]) -> Result<PlatformState, PlatformError> {
    PlatformState::new(db_path, db_key)
}

///
/// Delete a PlatformState.
///
pub fn state_delete(db_path: String) -> Result<(), PlatformError> {
    PlatformState::delete(db_path)
}

///
/// Group Configuration
///

// Assuming GroupConfig is a struct
#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub ciphersuite: CipherSuite,
    pub version: ProtocolVersion,
    pub options: ExtensionList,
}

impl Default for GroupConfig {
    fn default() -> Self {
        GroupConfig {
            // Set default ciphersuite.
            ciphersuite: CipherSuite::CURVE25519_AES128,
            // Set default protocol version.
            version: ProtocolVersion::MLS_10,
            // Set default options.
            options: ExtensionList::new(),
        }
    }
}

///
/// Generate a credential.
///

// ? Do we want to keep this at all ?
pub fn mls_generate_credential_basic(name: &str) -> Result<BasicCredential, PlatformError> {
    let credential = mls_rs::identity::basic::BasicCredential::new(name.as_bytes().to_vec());
    Ok(credential)
}

///
/// Generate a Signature Keypair
///
pub fn mls_generate_signature_keypair(
    state: &mut PlatformState,
    cs: CipherSuite,
    // _randomness: Option<Vec<u8>>,
) -> Result<Vec<u8>, PlatformError> {
    let crypto_provider = DefaultCryptoProvider::default();
    let cipher_suite = crypto_provider
        .cipher_suite_provider(cs)
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    // Generate a signature key pair.
    let (signature_key, signature_pubkey) = cipher_suite
        .signature_key_generate()
        .map_err(|_| PlatformError::UnsupportedCiphersuite)?;

    let identifier = todo!(); // Sha256::sha256(&signature_pubkey);

    // // Create the credential and the signing identity.
    // let credential = mls_generate_credential(myself)?;
    // let signing_identity: SigningIdentity =
    //     SigningIdentity::new(credential.into_credential(), signature_pubkey);

    // // Retrieve the identifier bytes (they should be identical to myself)
    // let identifier_bytes: Vec<u8> = DefaultIdentityProvider::new()
    //     .identity(&signing_identity, &Default::default())
    //     .map_err(|e| MlsError::IdentityError(e.into_any_error()))?;

    // Print the signature key
    println!("Signature Secret Key: {:?}", hex::encode(&signature_key));
    println!("Signature Identifier: {:?}", hex::encode(&identifier));
    // // Store the signature key pair.
    // let _ = state.insert_sigkey(&identifier_bytes, &signing_identity, &signature_key, cs);

    Ok(identifier)
}

///
/// Generate a KeyPackage.
///
pub fn mls_generate_key_package(
    state: &PlatformState,
    myself: Identity,
    // Below is group config
    cs: CipherSuite,
    _credential: Credential,
    // version: ProtocolVersion, <- Avoid app to set this, the platform should set it
    // Below is client config
    _key_package_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
    // _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, PlatformError> {
    // Create a client for that artificial state
    let zzz_group_config = GroupConfig {
        ciphersuite: cs,
        version,
        options: ExtensionList::new(),
    };
    let client = state.client(&myself, &zzz_group_config)?;

    // Generate a KeyPackage from that Client
    let key_package = client.generate_key_package_message()?;
    // let kp_bytes = key_package.mls_encode_to_vec()?;
    Ok(key_package)
}

///
/// Get group members.
///
pub type MlsMembers = (u64, Vec<(Identity, Credential)>);

pub fn mls_members(
    state: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    // TODO: Should be removed
    group_config: Option<GroupConfig>,
    // Change
) -> Result<MlsMembers, PlatformError> {
    let group = state.client(myself, group_config)?.load_group(gid)?;
    let epoch = group.current_epoch();

    // Return (Identity, Credential)
    let members = group
        .roster()
        .member_identities_iter()
        .map(|identity| Ok((mls_identity(identity)?, identity.clone())))
        .collect::<Result<Vec<_>, PlatformError>>()?;

    unimplemented!("Return the members");
    // Return JSON ?
    Ok((epoch, members))
    // return Json(MlsMembers {
    //     epoch,
    //     members,
    // });
}

///
/// Get the current epoch.
///

pub type GroupContext = Vec<u8>; // TODO

pub fn mls_group_context(
    state: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
) -> Result<GroupContext, PlatformError> {
    unimplemented!()
    // return Json(GroupContext {
    // ...
    // });
}

// ///
// /// Get the Identity from a SigningIdentity.
// ///
// pub fn mls_identity(
//     signing_identity: &SigningIdentity,
//     // cs: CipherSuite,
// ) -> Result<Identity, MlsError> {
//     let identity_bytes = DefaultIdentityProvider::new()
//         .identity(&signing_identity, &Default::default())
//         .map_err(|e| MlsError::IdentityError(e.into_any_error()))?;
//     Ok(identity_bytes)
//     // DefaultCryptoProvider::default()
//     //     .cipher_suite_provider(cs)
//     //     .ok_or(MlsError::UnsupportedCiphersuite)?
//     //     .hash(&signing_identity.mls_encode_to_vec()?)
//     //     .map(Identity)
//     //     .map_err(|e| MlsError::IdentityError(e.into_any_error()))
// }

///
/// Group management: Create a Group
///
pub fn mls_group_create(
    pstate: &mut PlatformState,
    myself: &Identity,
    gid: Option<GroupId>,
    // Below is group config
    cs: CipherSuite,
    _credential: Credential,
    // version: ProtocolVersion, <- Avoid app to set this, the platform should set it
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
    // TODO: Client config++
) -> Result<GroupId, PlatformError> {
    // Build the client
    let client = pstate.client(myself, group_config.clone())?;

    // Create a group context extension if none is provided
    let gce = match group_config {
        Some(c) => c.options,
        None => ExtensionList::new(),
    };

    // Generate a GroupId if none is provided
    let mut group = match gid {
        Some(gid) => client.create_group_with_id(gid, gce)?,
        None => client.create_group(gce)?,
    };

    // Create the group
    group.commit(Vec::new())?;
    group.apply_pending_commit()?;

    // The state needs to be returned or stored somewhere
    group.write_to_storage()?;
    let gid = group.group_id().to_vec();

    // Return
    Ok(gid)
}

///
/// Group management: Adding a user.
///

pub struct MlsCommitOutput {
    commit: MlsMessage,
    welcome: Option<MlsMessage>,
    group_info: Option<MlsMessage>,
    ratchet_tree: Option<Vec<u8>>,
}

pub fn mls_group_add(
    pstate: &mut PlatformState,
    gid: &GroupId,
    myself: &Identity,
    new_members: Vec<MlsMessage>,
) -> Result<MlsCommitOutput, PlatformError> {
    // Get the group from the state
    let client = pstate.client(myself, group_config)?;
    let mut group = client.load_group(gid)?;

    let mut commit = new_members
        .into_iter()
        .try_fold(group.commit_builder(), |commit_builder, user| {
            commit_builder.add_member(user)
        })?
        .build()?;

    // We use the default mode which returns only one welcome message
    let welcome = commit.welcome_messages.remove(0);
    let commit = commit.commit_message;

    // Write the group to the storage
    group.write_to_storage()?;

    unimplemented!()
}

pub fn mls_group_propose_add(
    _pstate: &mut PlatformState,
    _gid: &GroupId,
    _myself: Identity,
    _new_members: Vec<MlsMessage>,
) -> Result<Vec<MlsMessage>, PlatformError> {
    unimplemented!()
}

///
/// Group management: Removing a user.
///
pub fn mls_group_remove(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    removed: Vec<Identity>,
) -> Result<MlsCommitOutput, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .ok_or(MlsError::UndefinedSigningIdentity)?;

    let commit = group.commit_builder().remove_member(removed)?.build()?;
    unimplemented!();
    Ok(commit.commit_message)
}

pub fn mls_group_propose_remove(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    removed: Vec<Identity>,
) -> Result<Vec<MlsMessage>, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .ok_or(MlsError::UndefinedSigningIdentity)?;

    let proposal = group.propose_remove(removed, vec![])?;
    unimplemented!();
    Ok(proposal)
}

///
/// Key updates
///

pub struct MlsGroupUpdate {
    identity: Identity,
    commit_output: MlsCommitOutput,
}

/// Possibly add a random nonce as an optional parameter.
pub fn mls_group_update(
    pstate: &mut PlatformState,
    gid: GroupId,
    myself: &Identity,
    signature_key: Option<Vec<u8>>,
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
) -> Result<MlsGroupUpdate, PlatformError> {
    // Propose + Commit
    let client = pstate.client(myself, None)?;
    let mut group = client.load_group(&gid)?;
    let commit = group.commit(vec![])?;

    group.write_to_storage()?;

    Ok(commit.commit_message)
}

pub fn mls_group_propose_update(
    pstate: &mut PlatformState,
    gid: GroupId,
    myself: &Identity,
    signature_key: Option<Vec<u8>>,
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
) -> Result<MlsMessage, PlatformError> {
    unimplemented!()
}
// TODO: When do we signal the app that the signature identity has changed ?

///
/// Process Welcome message.
///

// TODO: Expose auditable
pub struct PendingJoinState {
    identifier: Vec<u8>,
}

pub fn mls_group_process_welcome(
    pstate: &PlatformState,
    myself: &Identity,
    welcome: MlsMessage,
    ratchet_tree: Option<ExportedTree<'static>>,
) -> Result<PendingJoinState, PlatformError> {
    let client = pstate.client(myself, group_config)?;
    let (mut group, _info) = client.join_group(ratchet_tree, welcome)?;
    let gid = group.group_id().to_vec();

    // Store the state
    group.write_to_storage()?;

    // Return the group identifier
    Ok(gid)
}

pub fn mls_group_process_welcome(
    pstate: &PlatformState,
    myself: &Identity,
    welcome: MlsMessage,
    ratchet_tree: Option<ExportedTree<'static>>,
) -> Result<PendingJoinState, PlatformError> {
}

pub fn mls_group_confirm_join(
    pstate: &PlatformState,
    myself: &Identity,
    reference_welcome: PendingJoinState,
) -> Result<GroupId, PlatformError> {
    let client = pstate.client(myself, group_config)?;
    let (mut group, _info) = client.join_group(ratchet_tree, welcome)?;
    let gid = group.group_id().to_vec();

    // Store the state
    group.write_to_storage()?;

    // Return the group identifier
    Ok(gid)
}

///
/// Leave a group.
///
// TODO: Do we keep this ?
pub fn mls_group_propose_leave(
    pstate: PlatformState,
    gid: GroupId,
    myself: &Identity,
    group_config: Option<GroupConfig>,
) -> Result<mls_rs::MlsMessage, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;
    let self_index = group.current_member_index();
    let proposal = group.propose_remove(self_index, vec![])?;

    Ok(proposal)
}

///
/// Close a group by removing all members.
///

// TODO would this be better with a custom proposal? <- Yes.
pub fn mls_group_close(
    pstate: PlatformState,
    gid: GroupId,
    myself: &Identity,
    group_config: Option<GroupConfig>,
) -> Result<mls_rs::MlsMessage, PlatformError> {
    // Remove everyone from the group.
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;
    let self_index = group.current_member_index();

    let all_but_me = group
        .roster()
        .members_iter()
        .filter_map(|m| (m.index != self_index).then_some(m.index))
        .collect::<Vec<_>>();

    let commit = all_but_me
        .into_iter()
        .try_fold(group.commit_builder(), |builder, index| {
            builder.remove_member(index)
        })?
        .build()?;

    // TODO we should delete state when we receive an ACK. but it's not super clear how to
    // determine on receive that this was a "close" commit. Would be easier if we had a custom
    // proposal

    Ok(commit.commit_message)
}

///
/// Process a non-Welcome message from the app.
///
/// Note: when the higher level APIs (e.g., Java in case of Android) receives a message,
/// it checks with the apps via callbacks whether the apps want to proceed with the message
/// (e.g., if the message is a Commit, the app might not want to apply it due to ACL).
/// That means the moment a message is passed down to this Rust layer, it'll be processed
/// as prescribed by MLS:
///  - A Proposal will result in a Commit.
///  - A Commit will result in it being applied to advance the group state.
///  - An application message will result in it being decrypted.
///

pub fn mls_receive(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    message_or_ack: MlsMessageOrAck,
    group_config: Option<GroupConfig>,
) -> Result<Vec<u8>, PlatformError> {
    // TODO: Do we need the GID as input since it is in the message framing ?
    let mut group = pstate.client(myself, group_config)?.load_group(gid)?;

    let out = match message_or_ack {
        MlsMessageOrAck::Ack => group.apply_pending_commit().map(ReceivedMessage::Commit),
        MlsMessageOrAck::MlsMessage(message) => group.process_incoming_message(message),
    };

    //
    let result = match out? {
        ReceivedMessage::ApplicationMessage(app_data_description) => {
            app_data_description.data().to_vec()
        }
        // TODO: Return the serialized message if not an application message
        _ => "Not an Application Message".as_bytes().to_vec(),
    };

    // Write the state to storage
    group.write_to_storage()?;

    Ok(result)
}

//
// Encrypt a message.
//

pub fn mls_send(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    message: &[u8],
    group_config: Option<GroupConfig>,
) -> Result<MlsMessage, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(gid)?;

    let out = group.encrypt_application_message(message, vec![])?;
    group.write_to_storage()?;

    Ok(out)
}

///
/// Propose + Commit a GroupContextExtension
///
pub fn mls_send_groupcontextextension(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    new_gce: Vec<Extension>,
    group_config: Option<GroupConfig>,
) -> Result<mls_rs::MlsMessage, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let commit = group
        .commit_builder()
        .set_group_context_ext(new_gce.into())?
        .build()?;

    Ok(commit.commit_message)
}

///
/// Create and send a custom proposal.
///
pub fn mls_send_custom_proposal(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    proposal_type: ProposalType,
    data: Vec<u8>,
    group_config: Option<GroupConfig>,
) -> Result<mls_rs::MlsMessage, PlatformError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;
    let custom_proposal = CustomProposal::new(proposal_type, data);
    let proposal = group.propose_custom(custom_proposal, vec![])?;

    Ok(proposal)
}

///
/// Export a group secret.
///
pub fn mls_export(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    label: &[u8],
    context: &[u8],
    len: u64,
    group_config: Option<GroupConfig>,
    // TODO: epoch_number: Option<u64>, this is not supported in the current version of mls-rs
) -> Result<(Vec<u8>, u64), PlatformError> {
    let group = pstate.client(myself, group_config)?.load_group(gid)?;
    let secret = group
        .export_secret(label, context, (len as u64).try_into().unwrap())?
        .to_vec();
    Ok((secret, group.current_epoch()))
}
