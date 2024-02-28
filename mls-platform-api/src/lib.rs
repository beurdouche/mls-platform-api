mod state;

use mls_rs::error::{AnyError, IntoAnyError};
use mls_rs::group::proposal::{CustomProposal, ProposalType};
use mls_rs::group::{Capabilities, ExportedTree, ReceivedMessage};
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
    #[error("UndefinedIdentity")]
    UndefinedIdentity,
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

    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cs)
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    let identifier = cipher_suite_provider
        .hash(&signature_pubkey)
        .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

    // Print the signature key
    println!("Signature Secret Key: {:?}", hex::encode(&signature_key));
    println!("Signature Identifier: {:?}", hex::encode(&identifier));

    // Store the signature key pair.
    let _ = state.insert_sigkey(&signature_key, cs);

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
    credential: Credential,
    // version: ProtocolVersion, <- Avoid app to set this, the platform should set it
    // Below is client config
    key_package_extensions: Option<ExtensionList>,
    leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
    // _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, PlatformError> {
    // Create a client for that artificial state
    let client = state.client(
        &myself,
        ProtocolVersion::MLS_10,
        key_package_extensions,
        leaf_node_extensions,
        None,
        None,
    )?;

    // Generate a KeyPackage from that client_default
    let key_package = client.generate_key_package_message()?;
    // let kp_bytes = key_package.mls_encode_to_vec()?;
    Ok(key_package)
}

///
/// Get group members.
///

#[derive(Clone, Debug, PartialEq)]
pub struct MlsMembers {
    epoch: u64,
    identities: Vec<(Identity, Credential)>,
}

pub fn mls_members(
    state: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
) -> Result<MlsMembers, PlatformError> {
    let crypto_provider = DefaultCryptoProvider::default();

    let group = state.client_default(myself)?.load_group(gid)?;
    let epoch = group.current_epoch();

    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    // Return Vec<(Identity, Credential)>
    let identities = group
        .roster()
        .member_identities_iter()
        .map(|identity| {
            Ok((
                cipher_suite_provider
                    .hash(&identity.signature_key)
                    .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?,
                identity.credential.clone(),
            ))
        })
        .collect::<Result<Vec<_>, PlatformError>>()?;

    let res = MlsMembers { epoch, identities };

    Ok(res)
    // serde_json::to_string(&res)?.as_bytes()
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

// version: ProtocolVersion, <- Avoid app to set this, the platform should set it

pub fn mls_group_create(
    pstate: &mut PlatformState,
    myself: &Identity,
    gid: Option<GroupId>,
    // Group config
    cs: CipherSuite,
    _credential: Credential,
    // Client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    _leaf_node_capabilities: Option<Capabilities>,
    // lifetime: Option<u64>,
) -> Result<GroupId, PlatformError> {
    // Build the client
    let client = pstate.client_default(myself)?;

    // Generate a GroupId if none is provided
    let mut group = match gid {
        Some(gid) => {
            client.create_group_with_id(gid, _group_context_extensions.unwrap_or_default())?
        }
        None => client.create_group(_group_context_extensions.unwrap_or_default())?,
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
    pub commit: MlsMessage,
    pub welcome: Vec<MlsMessage>,
    pub group_info: Option<MlsMessage>,
    pub ratchet_tree: Option<Vec<u8>>,
    // pub unused_proposals: Vec<crate::mls_rules::ProposalInfo<Proposal>>, from mls_rs
}

pub fn mls_group_add(
    pstate: &mut PlatformState,
    gid: &GroupId,
    myself: &Identity,
    new_members: Vec<MlsMessage>,
) -> Result<Vec<MlsCommitOutput>, PlatformError> {
    // Get the group from the state
    let client = pstate.client_default(myself)?;
    let mut group = client.load_group(gid)?;

    let mut commit_output = new_members
        .into_iter()
        .try_fold(group.commit_builder(), |commit_builder, user| {
            commit_builder.add_member(user)
        })?
        .build()?;

    // We use the default mode which returns only one welcome message
    let welcome = commit_output.welcome_messages.remove(0);

    let commit_output = MlsCommitOutput {
        commit: commit_output.commit_message.clone(),
        welcome: vec![welcome], // TODO: This could be the direct mapping
        group_info: commit_output.external_commit_group_info,
        ratchet_tree: None, // TODO: Is this ok for that welcome mode ?
    };

    // Write the group to the storage
    group.write_to_storage()?;

    Ok(vec![commit_output])
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
    removed: Identity, // TODO: Make this Vec<Identities>?
) -> Result<MlsCommitOutput, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;

    let crypto_provider = DefaultCryptoProvider::default();

    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| {
            let h = cipher_suite_provider
                .hash(&m.signing_identity.signature_key)
                .ok()?;
            (h == removed).then_some(m.index)
        })
        .ok_or(PlatformError::UndefinedIdentity)?;

    let commit = group.commit_builder().remove_member(removed)?.build()?;

    let commit_output = MlsCommitOutput {
        commit: commit.commit_message,
        welcome: commit.welcome_messages,
        group_info: commit.external_commit_group_info,
        ratchet_tree: commit
            .ratchet_tree
            .map(|tree| tree.to_bytes())
            .transpose()?,
    };

    Ok(commit_output)
}

pub fn mls_group_propose_remove(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    removed: Identity, // TODO: Handle Vec<Identity>
) -> Result<MlsMessage, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;

    let crypto_provider = DefaultCryptoProvider::default();

    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| {
            let h = cipher_suite_provider
                .hash(&m.signing_identity.signature_key)
                .ok()?;
            (h == removed).then_some(m.index)
        })
        .ok_or(PlatformError::UndefinedIdentity)?;

    let proposal = group.propose_remove(removed, vec![])?;
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
    myself: Identity,
    signature_key: Option<Vec<u8>>,
    credential: Option<Credential>,
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    // TODO: Define type for capabilities
    _leaf_node_capabilities: Option<Vec<u8>>,
    // lifetime: Option<u64>,
) -> Result<MlsGroupUpdate, PlatformError> {
    let crypto_provider = DefaultCryptoProvider::default();

    // Propose + Commit
    let client = pstate.client_default(&myself)?;
    let mut group = client.load_group(&gid)?;

    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or(PlatformError::UnsupportedCiphersuite)?;

    let (commit, identity) = if let Some((key, cred)) = signature_key.zip(credential) {
        let signature_secret_key = key.into();
        let signature_public_key = cipher_suite_provider
            .signature_key_derive_public(&signature_secret_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

        let signing_identity = SigningIdentity::new(cred, signature_public_key);
        let identity = cipher_suite_provider
            .hash(&signing_identity.signature_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;
        let commit = group
            .commit_builder()
            .set_new_signing_identity(signature_secret_key, signing_identity)
            .build()?;

        (commit, identity)
    } else {
        let commit = group.commit(vec![])?;

        (commit, myself)
    };

    group.write_to_storage()?;

    let commit_output = MlsCommitOutput {
        commit: commit.commit_message,
        welcome: commit.welcome_messages,
        group_info: commit.external_commit_group_info,
        ratchet_tree: commit
            .ratchet_tree
            .map(|tree| tree.to_bytes())
            .transpose()?,
    };
    // Generate the signature keypair
    // Return the signing Identity
    // Hash the signingIdentity to get the Identifier

    let group_update = MlsGroupUpdate {
        identity,
        commit_output,
    };
    Ok(group_update)
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

// pub fn mls_group_process_welcome(
//     pstate: &PlatformState,
//     myself: &Identity,
//     welcome: MlsMessage,
//     ratchet_tree: Option<ExportedTree<'static>>,
// ) -> Result<PendingJoinState, PlatformError> {
//     let client = pstate.client_default(myself)?;
//     let (mut group, _info) = client.join_group(ratchet_tree, welcome)?;
//     let gid = group.group_id().to_vec();

//     // Store the state
//     group.write_to_storage()?;

//     // Return the group identifier
//     Ok(gid)
// }

// pub fn mls_group_inspect_welcome(
//     pstate: &PlatformState,
//     myself: &Identity,
//     welcome: MlsMessage,
//     ratchet_tree: Option<ExportedTree<'static>>,
// ) -> Result<PendingJoinState, PlatformError> {
//     unimplemented!()
// }

pub fn mls_group_confirm_join(
    pstate: &PlatformState,
    myself: &Identity,
    welcome: MlsMessage,
    ratchet_tree: Option<ExportedTree<'static>>,
) -> Result<GroupId, PlatformError> {
    let client = pstate.client_default(myself)?;
    let (mut group, _info) = client.join_group(ratchet_tree, &welcome)?;
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
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;
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
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;
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
    let mut group = pstate.client_default(myself)?.load_group(gid)?;

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
    let mut group = pstate.client_default(myself)?.load_group(gid)?;

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
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;

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
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;
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
    let group = pstate.client_default(myself)?.load_group(gid)?;
    let secret = group
        .export_secret(label, context, (len as u64).try_into().unwrap())?
        .to_vec();
    Ok((secret, group.current_epoch()))
}
