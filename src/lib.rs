mod state;

use mls_rs::group::proposal::{CustomProposal, ProposalType};
use mls_rs::group::{ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::storage_provider::KeyPackageData;
// use mls_rs::storage_provider::GroupState;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::{CipherSuiteProvider, CryptoProvider, Extension, ExtensionList, IdentityProvider};
pub use state::{PlatformState, TemporaryState};

pub type DefaultCryptoProvider = mls_rs_crypto_rustcrypto::RustCryptoProvider;
pub type DefaultIdentityProvider = mls_rs::identity::basic::BasicIdentityProvider;

///
/// Errors
///
#[derive(Debug)]
pub enum MlsError {
    MlsError(mls_rs::error::MlsError),
    IdentityError,
}

impl From<mls_rs::error::MlsError> for MlsError {
    fn from(error: mls_rs::error::MlsError) -> Self {
        Self::MlsError(error)
    }
}

///
/// Generate a PlatformState.
///
pub fn create_state(db_path: String) -> PlatformState {
    PlatformState::new(db_path).unwrap()
}

// Definition of the GroupContext Extensions
#[derive(Debug)]
pub struct GroupContextExtensions {
    // Add fields as needed
}

// Definition of the type for the CipherSuite
pub use mls_rs::CipherSuite;
pub use mls_rs::ProtocolVersion;

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

/// Group configuration.
///
/// This is more or less only for Ciphersuites and GroupContext extensions
/// V8 - Update group context extensions
/// Discuss: do we want to pass the version number explicitly to avoid compat problems with future versions ? (likely yes)
///
/// # Parameters
/// - `external_sender`: Availibility of the external sender extension
///   - Default: None (We don't expose that)
/// - `required_capabilities`: Needed to specify extensions
///   - Option: None (Expose the ability to provide a 3-tuple of Vec<u8>)
///
/// Note, external_sender is an Extension but other config options  might be different

pub fn mls_create_group_config(
    cs: CipherSuite,
    v: ProtocolVersion,
    options: ExtensionList,
) -> Result<GroupConfig, MlsError> {
    Ok(GroupConfig {
        ciphersuite: cs,
        version: v,
        options,
    })
}

/// Client configuration.
///
/// V8  - We could require the library to update the client configuration at runtime
/// Options:
/// - WireFormatPolicy
///     - Default: None (We don't expose that)
/// - padding_size
///     - Default: to some to complete the block to 64 bytes (pick a good value)
/// - max_past_epochs
///     - This is for application messages (cross-epoch)
///     - Option: set the default some small value
/// - number_of_resumption_psks
///     - Default: 0 (We don't expose that)
/// - use_ratchet_tree_extension
///     - Option: default to true
/// - out_of_order_tolerance
///     - This is within an epoch
///     - Option: set the default to small number
/// - maximum_forward_distance
///     - Maximum generation forward within an epoch from the same sender
///     - Default: set to something like 1000 (Signal uses 2000)
/// - Lifetime
///     - Lifetime of a keypackage
///     - This is to indicate the amount of time before which an update needs to happen

pub struct ClientConfig {
    // Add fields as needed
}

// Question: should clients have consistent values for ratchet_tree_exrtensions
pub fn mls_create_client_config(
    max_past_epoch: Option<u32>,
    use_ratchet_tree_extension: bool,
    out_of_order_tolerance: Option<u32>,
    maximum_forward_distance: Option<u32>,
) -> Result<ClientConfig, MlsError> {
    unimplemented!()
}

///
/// Generate Signature Key Pair
///
use mls_rs::crypto::SignaturePublicKey;
use mls_rs::crypto::SignatureSecretKey;

#[derive(Debug)]
pub struct SignatureKeypair {
    pub secret: SignatureSecretKey,
    pub public: SignaturePublicKey,
}

pub fn serialize_signing_identity(
    signing_identity: &SigningIdentity,
) -> Result<Vec<u8>, mls_rs::mls_rs_codec::Error> {
    Ok(signing_identity.mls_encode_to_vec()?)
}

pub fn deserialize_signing_identity(
    bytes: &[u8],
) -> Result<SigningIdentity, mls_rs::mls_rs_codec::Error> {
    Ok(SigningIdentity::mls_decode(&mut bytes.as_ref())?)
}

// Stateless function
pub fn mls_stateless_generate_signature_keypair(
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<(SigningIdentity, SignatureSecretKey), MlsError> {
    let crypto_provider = DefaultCryptoProvider::default();
    let cipher_suite = crypto_provider.cipher_suite_provider(cs).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    // Create the credential and the signing identity.
    // TODO: Handle X.509 certificates
    let credential = generate_credential(name)?;
    let signing_identity: SigningIdentity =
        SigningIdentity::new(credential.into_credential(), public);

    Ok((signing_identity, secret))
}

// Stateful function
pub fn mls_generate_signature_keypair(
    state: &mut PlatformState,
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<SigningIdentity, MlsError> {
    // Generate the signature key pair and the siging identity.
    let (myself, myself_sigkey) = mls_stateless_generate_signature_keypair(name, cs, _randomness)?;

    // Print the signature key pair
    println!("Signature Secret Key: {:?}", hex::encode(&myself_sigkey));

    // Store the signature key pair.
    state.insert_sigkey(&myself, &myself_sigkey, cs);
    Ok(myself)
}

///
/// Generate a credential.
///
use mls_rs::identity::basic::BasicCredential;

pub fn generate_credential(name: &str) -> Result<BasicCredential, MlsError> {
    let credential = mls_rs::identity::basic::BasicCredential::new(name.as_bytes().to_vec());
    Ok(credential)
}

/// Generate a KeyPackage.
///
/// This function generates a KeyPackage based on the provided GroupConfig and SignatureKey.
///
/// # Arguments
/// - `group_config`: The configuration of the group.
/// - `signature_key`: The signature key used for the KeyPackage.
///
/// # Returns
/// - `Ok(KeyPackage)`: The generated KeyPackage.
/// - `Err(MLSError)`: An error occurred during the generation process.
///

// TODO: Look into capabilities that might be missing here...

pub fn mls_stateless_generate_key_package(
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
    myself_sigkey: SignatureSecretKey,
    _randomness: Option<Vec<u8>>,
) -> Result<(MlsMessage, KeyPackageData), MlsError> {
    let mut state = TemporaryState::new();

    state.insert_sigkey(
        &myself,
        &myself_sigkey,
        // TODO make default config if None
        group_config.clone().unwrap().ciphersuite,
    );

    let client = state.client(myself, group_config)?;
    let key_package = client.generate_key_package_message()?;

    let mut state = state.key_packages.lock().unwrap();
    let key = state.keys().next().unwrap().clone();

    let key_package_data = state.remove(&key).unwrap();

    Ok((key_package, key_package_data.key_package_data))
}

// Add rng: Option<[u8; 32]>
pub fn generate_key_package(
    state: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    _randomness: Option<Vec<u8>>,
) -> Result<mls_rs::MlsMessage, MlsError> {
    // Create a client for that artificial state
    let client = state.client(myself, group_config)?;

    // Generate a KeyPackage from that Client
    let key_package = client.generate_key_package_message()?;
    Ok(key_package)
}

///
/// Get group members.
///
#[derive(Clone, Debug)]
pub struct Identity(Vec<u8>); // "google.com@groupId@clientId" <-> SigningIdentity
pub struct Epoch {} // u32 // u64?

pub fn mls_members(
    state: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    gid: &GroupId,
) -> Result<(u64, Vec<(Identity, SigningIdentity)>), MlsError> {
    let group = state.client(myself, group_config)?.load_group(gid)?;

    let epoch = group.current_epoch();
    let extensions = group.context().extensions();
    let id_provider = DefaultIdentityProvider::default();

    let members = group
        .roster()
        .member_identities_iter()
        .map(|identity| {
            Ok((
                id_provider
                    .identity(identity, extensions)
                    .map(Identity)
                    .map_err(|_| MlsError::IdentityError)?,
                identity.clone(),
            ))
        })
        .collect::<Result<Vec<_>, MlsError>>()?;

    Ok((epoch, members))
}

/// To create a group for one person.
///
/// Note: the groupState is kept track of by the lib and is not returned to the app.
/// If at some point the app needs to get the MlsState, we'll support a getMlsState(GroupId) function.
///
/// Note: this function underneath will write down the GroupState in its persistent storage.
/// https://github.com/awslabs/mls-rs/blob/main/mls-rs-provider-sqlite/src/connection_strategy.rs
pub type GroupId = Vec<u8>;
pub type GroupState = Vec<u8>;

pub fn mls_create_group(
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
/// Two cases depending on access control from the app:
///
/// Case 1: the proposer can commit.
/// Case 2: the proposer cannot commit, they can only propose.
///
/// The application should be able to decide this based on their access control
/// either on client side or server side (eg the user X doesn't have permission
/// to approve add requests to a groupID).

pub type MlsMessage = mls_rs::MlsMessage;

// TODO: This should not be "add user" but maybe "group add" instead.
pub fn mls_add_user(
    pstate: &mut PlatformState,
    gid: &GroupId,
    group_config: Option<GroupConfig>,
    user: Vec<MlsMessage>,
    myself: SigningIdentity,
) -> Result<(MlsMessage, MlsMessage), MlsError> {
    // Get the group from the state
    let client = pstate.client(myself, group_config)?;
    let mut group = client.load_group(gid)?;

    let mut commit = user
        .into_iter()
        .try_fold(group.commit_builder(), |commit_builder, user| {
            commit_builder.add_member(user)
        })?
        .build()?;

    let welcome = commit.welcome_messages.remove(0);
    let commit = commit.commit_message;

    group.write_to_storage()?;

    Ok((commit, welcome))
}

// TODO: Implement this !
// pub fn mls_propose_add_user(
//     gid: GroupId,
//     user: KeyPackage,
//     my_identity: SigningIdentity,
// ) -> Result<MlsMessage, MlsError> {
//     unimplemented!()
// }

///
/// Group management: Removing a user.
///

// We can't really use the KeyPackage to remove a user.
// We need to use the identity of the user to remove them.

pub fn mls_rem_member(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    removed: SigningIdentity,
    myself: SigningIdentity,
) -> Result<mls_rs::MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    // TODO introduce custom error type for this lib
    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .unwrap();

    let commit = group.commit_builder().remove_member(removed)?.build()?;

    Ok(commit.commit_message)
}

pub fn mls_propose_rem_user(
    pstate: &PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    removed: SigningIdentity,
    myself: SigningIdentity,
) -> Result<mls_rs::MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;

    // TODO introduce custom error type for this lib
    let removed = group
        .roster()
        .members_iter()
        .find_map(|m| (m.signing_identity == removed).then_some(m.index))
        .unwrap();

    let proposal = group.propose_remove(removed, vec![])?;

    Ok(proposal)
}

///
/// Key updates
///
/// Note: Everyone is able to propose and commit to their key update.
///

/// Should we rename that commit ?
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

pub enum MlsMessageOrAck {
    Ack,
    MlsMessage(MlsMessage),
}

pub fn mls_process_received_message(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: SigningIdentity,
    message_or_ack: MlsMessageOrAck,
    group_config: Option<GroupConfig>,
) -> Result<ReceivedMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(gid)?;

    let out = match message_or_ack {
        MlsMessageOrAck::Ack => group.apply_pending_commit().map(ReceivedMessage::Commit),
        MlsMessageOrAck::MlsMessage(message) => group.process_incoming_message(message),
    };

    group.write_to_storage()?;

    Ok(out?)
}

// https://docs.rs/mls-rs/latest/mls_rs/group/mls_rules/trait.MlsRules.html#tymethod.filter_proposals

///
/// Process Welcome message.
///
/// Note: A Welcome will be processed to create a group object
/// for the invited member.
///

pub struct RatchetTree {}

pub fn mls_process_received_join_message(
    pstate: &PlatformState,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    welcome: MlsMessage,
    ratchet_tree: Option<ExportedTree<'static>>,
) -> Result<(), MlsError> {
    let client = pstate.client(myself, group_config)?;
    let (mut group, _info) = client.join_group(ratchet_tree, welcome)?;
    group.write_to_storage()?;

    Ok(())
}

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

// To leave the group
pub fn mls_leave(
    pstate: PlatformState,
    gid: GroupId,
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
) -> Result<mls_rs::MlsMessage, MlsError> {
    let mut group = pstate.client(myself, group_config)?.load_group(&gid)?;
    let self_index = group.current_member_index();
    let proposal = group.propose_remove(self_index, vec![])?;

    // Leave and zero out all the states: RemoveProposal
    // TODO do we want to delete the state before we know proposal was committed?
    pstate.delete().unwrap();

    Ok(proposal)
}

// To close a group i.e., removing all members of the group.
// TODO would this be better with a custom proposal?
pub fn mls_close(
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

//
// Encrypt a message.
//

pub fn mls_encrypt_message(
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
/// Get the group state.
///
/// With PublicGroupState + signatureKey + HPKE key one can rebuild everything.

pub struct PublicGroupState {}

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

    // TODO what is the second tuple element?
    Ok((secret, 0))
}

///
/// Import a group state into the storage
///
// TODO is this needed?
pub fn mls_import_group_state(
    group_state: Vec<u8>,
    signature_key: SignatureKeypair,
    myself: SigningIdentity,
) -> Result<(), MlsError> {
    unimplemented!()
    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/client.rs#L605
}

pub fn mls_export_group_state(gid: GroupId) -> Result<PublicGroupState, MlsError> {
    unimplemented!()
}

// ///
// /// Validate a KeyPackage.
// ///
//
// We could internalize the KeyPackage validation in the Group operations.
//
// TODO: Might need to pass the GroupConfig here as well.
// pub fn validate_key_package(key_package: KeyPackage) -> Result<(), MlsError> {
//     unimplemented!()
//     // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/external_client.rs#L104
// }

// ///
// /// Extract Signing Identity from a KeyPackage.
// ///

// // TODO: Discuss if it shouldn't return a SignaturePublicKey instead.

// pub fn signing_identity_from_key_package(
//     key_package: KeyPackage,
// ) -> Result<SignaturePublicKey, MlsError> {
//     unimplemented!()
// }
