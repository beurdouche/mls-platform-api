mod state;

use mls_rs::group::proposal::{CustomProposal, ProposalType};
use mls_rs::group::{ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::{CipherSuiteProvider, CryptoProvider, Extension, ExtensionList};

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
#[derive(Clone, Debug)]
pub struct Identity(Vec<u8>);

#[allow(clippy::large_enum_variant)]
pub enum MlsMessageOrAck {
    Ack,
    MlsMessage(MlsMessage),
}

///
/// Errors
///
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error(transparent)]
    MlsError(#[from] mls_rs::error::MlsError),
    #[error("IdentityError")]
    IdentityError,
    #[error("UnsupportedCiphersuite")]
    UnsupportedCiphersuite,
    #[error("UnsupportedGroupConfig")]
    UnsupportedGroupConfig,
    #[error("UndefinedSigningIdentity")]
    UndefinedSigningIdentity,
    #[error("EncodingError")]
    EncodingError,
    #[error("SerializationError")]
    SerializationError,
    #[error("DeserializationError")]
    DeserializationError,
    #[error("StorageError")]
    StorageError,
    #[error("UnavailableSecret")]
    UnavailableSecret,
    #[error("MutexError")]
    MutexError,
    #[error(transparent)]
    MlsCodecError(#[from] mls_rs::mls_rs_codec::Error),
}

///
/// Generate or Retrieve a PlatformState.
///
pub fn state(db_path: String, db_key: [u8; 32]) -> Result<PlatformState, MlsError> {
    PlatformState::new(db_path, db_key)
}

///
/// Delete a PlatformState.
///
pub fn state_delete(db_path: String) -> Result<(), MlsError> {
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
/// Helper functions for SigningIdentity
///
pub fn serialize_signing_identity(
    signing_identity: &SigningIdentity,
) -> Result<Vec<u8>, mls_rs::mls_rs_codec::Error> {
    signing_identity.mls_encode_to_vec()
}

pub fn deserialize_signing_identity(
    bytes: &[u8],
) -> Result<SigningIdentity, mls_rs::mls_rs_codec::Error> {
    SigningIdentity::mls_decode(&mut &*bytes)
}

///
/// Generate a credential.
///
pub fn mls_generate_credential(name: &str) -> Result<BasicCredential, MlsError> {
    let credential = mls_rs::identity::basic::BasicCredential::new(name.as_bytes().to_vec());
    Ok(credential)
}

///
/// Generate a Signature Keypair
///
pub fn mls_generate_signature_keypair(
    state: &mut PlatformState,
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<SigningIdentity, MlsError> {
    let crypto_provider = DefaultCryptoProvider::default();
    let cipher_suite = crypto_provider
        .cipher_suite_provider(cs)
        .ok_or(MlsError::UnsupportedCiphersuite)?;

    // Generate a signature key pair.
    let (signature_key, signature_pubkey) = cipher_suite
        .signature_key_generate()
        .map_err(|_| MlsError::UnsupportedCiphersuite)?;

    // Create the credential and the signing identity.
    // TODO: Handle X.509 certificates
    let credential = mls_generate_credential(name)?;
    let signing_identity: SigningIdentity =
        SigningIdentity::new(credential.into_credential(), signature_pubkey);

    // Print the signature key
    println!("Signature Secret Key: {:?}", hex::encode(&signature_key));

    // Store the signature key pair.
    let _ = state.insert_sigkey(&signing_identity, &signature_key, cs);
    Ok(signing_identity)
}

///
/// Generate a KeyPackage.
///
pub fn mls_generate_key_package(
    state: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, MlsError> {
    // Create a client for that artificial state
    let client = state.client(myself, group_config)?;

    // Generate a KeyPackage from that Client
    let key_package = client.generate_key_package_message()?;
    Ok(key_package)
}

///
/// Get group members.
///
pub fn mls_members(
    state: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    gid: &GroupId,
) -> Result<(u64, Vec<(Identity, SigningIdentity)>), MlsError> {
    let gc = group_config
        .clone()
        .ok_or(MlsError::UnsupportedGroupConfig)?;
    let cs = gc.ciphersuite;
    let group = state.client(myself, group_config)?.load_group(gid)?;
    let epoch = group.current_epoch();

    let members = group
        .roster()
        .member_identities_iter()
        .map(|identity| Ok((mls_identity(identity, cs)?, identity.clone())))
        .collect::<Result<Vec<_>, MlsError>>()?;

    Ok((epoch, members))
}

///
/// Get the Identity from a SigningIdentity.
///
pub fn mls_identity(
    signing_identity: &SigningIdentity,
    cs: CipherSuite,
) -> Result<Identity, MlsError> {
    DefaultCryptoProvider::default()
        .cipher_suite_provider(cs)
        .ok_or(MlsError::UnsupportedCiphersuite)?
        .hash(&signing_identity.mls_encode_to_vec()?)
        .map(Identity)
        .map_err(|_| MlsError::IdentityError)
}

///
/// Group management: Create a Group
///
pub fn mls_group_create(
    pstate: &mut PlatformState,
    group_config: Option<GroupConfig>,
    gid: Option<GroupId>,
    myself: SigningIdentity,
    // psk: Option<Vec<u8>>, // See if we pass that here or in all Group operations
) -> Result<GroupId, MlsError> {
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
pub fn mls_group_add(
    pstate: &mut PlatformState,
    gid: &GroupId,
    group_config: Option<GroupConfig>,
    new_members: Vec<MlsMessage>,
    myself: SigningIdentity,
) -> Result<(MlsMessage, MlsMessage), MlsError> {
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

    Ok((commit, welcome))
}

pub fn mls_group_propose_add(
    _pstate: &mut PlatformState,
    _gid: &GroupId,
    _group_config: Option<GroupConfig>,
    _new_members: Vec<MlsMessage>,
    _myself: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

///
/// Group management: Removing a user.
///
pub fn mls_group_remove(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    removed: SigningIdentity,
    myself: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .ok_or(MlsError::UndefinedSigningIdentity)?;

    let commit = group.commit_builder().remove_member(removed)?.build()?;

    Ok(commit.commit_message)
}

pub fn mls_group_propose_remove(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    removed: SigningIdentity,
    myself: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .ok_or(MlsError::UndefinedSigningIdentity)?;

    let proposal = group.propose_remove(removed, vec![])?;

    Ok(proposal)
}

///
/// Key updates
///

/// Possibly add a random nonce as an optional parameter.
pub fn mls_update(
    gid: GroupId,
    pstate: &mut PlatformState,
    myself: SigningIdentity,
    _rng: Option<[u8; 32]>,
) -> Result<MlsMessage, MlsError> {
    // Propose + Commit
    let client = pstate.client(myself, None)?;
    let mut group = client.load_group(&gid)?;
    let commit = group.commit(vec![])?;

    group.write_to_storage()?;

    Ok(commit.commit_message)
}

///
/// Process Welcome message.
///

pub fn mls_group_join(
    pstate: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    welcome: MlsMessage,
    ratchet_tree: Option<ExportedTree<'static>>,
) -> Result<Vec<u8>, MlsError> {
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
pub fn mls_group_propose_leave(
    pstate: PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
) -> Result<mls_rs::MlsMessage, MlsError> {
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
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
) -> Result<mls_rs::MlsMessage, MlsError> {
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
    myself: SigningIdentity,
    message_or_ack: MlsMessageOrAck,
    group_config: Option<GroupConfig>,
) -> Result<ReceivedMessage, MlsError> {
    // TODO: Do we need the GID as input since it is in the message framing ?
    let mut group = pstate.client(myself, group_config)?.load_group(gid)?;

    let out = match message_or_ack {
        MlsMessageOrAck::Ack => group.apply_pending_commit().map(ReceivedMessage::Commit),
        MlsMessageOrAck::MlsMessage(message) => group.process_incoming_message(message),
    };

    // Write the state to storage
    group.write_to_storage()?;

    Ok(out?)
}

///
/// Create and send a custom proposal.
///
pub fn mls_send_custom_proposal(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
    proposal_type: ProposalType,
    data: Vec<u8>,
) -> Result<mls_rs::MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;
    let custom_proposal = CustomProposal::new(proposal_type, data);
    let proposal = group.propose_custom(custom_proposal, vec![])?;

    Ok(proposal)
}

///
/// Propose + Commit a GroupContextExtension
///
pub fn mls_send_groupcontextextension(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
    new_gce: Vec<Extension>,
) -> Result<mls_rs::MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    let commit = group
        .commit_builder()
        .set_group_context_ext(new_gce.into())?
        .build()?;

    Ok(commit.commit_message)
}

//
// Encrypt a message.
//

pub fn mls_send(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    message: &[u8],
) -> Result<MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(gid)?;

    let out = group.encrypt_application_message(message, vec![])?;
    group.write_to_storage()?;

    Ok(out)
}

///
/// Export a group secret.
///
pub fn mls_export(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    label: &[u8],   // fixed by IANA registry
    context: &[u8], // arbitrary
    len: usize,     // exporting from past epoch is not supported because we didn't see use cases
    _epoch_number: Option<u32>,
) -> Result<(Vec<u8>, u32), MlsError> {
    // KDF of the secret of the current epoch.
    let group = pstate.client(myself, group_config)?.load_group(gid)?;
    let secret = group.export_secret(label, context, len)?.to_vec();

    // TODO what is the second tuple element? <- Epoch number
    Ok((secret, 0))
}
