use mls_rs::identity::SigningIdentity;
// use mls_rs::storage_provider::GroupState;
use mls_rs::{CipherSuiteProvider, CryptoProvider, ExtensionList};

// Definition of the type for the CipherSuite
pub use mls_rs::CipherSuite;

// Definition of the protocol version
#[derive(Debug)]
pub enum Version {
    MlsVersion10,
}

// Definition of the GroupContext Extensions
#[derive(Debug)]
pub struct GroupContextExtensions {
    // Add fields as needed
}

// Assuming GroupConfig is a struct
#[derive(Debug)]
pub struct GroupConfig {
    ciphersuite: CipherSuite,
    version: Version,
    options: ExtensionList,
}

#[derive(Debug)]
pub struct KeyPackage {
    kp: mls_rs::KeyPackage,
}

#[derive(Debug)]
pub struct MlsError {
    error: mls_rs::error::MlsError,
}

///
/// Generate Signature Key Pair
///
/// - Option: default to Basic Credentials
/// - Possibly use strings as the credential types have names
/// - (Alternatively we could use integers)
///
/// If we were to use enums we couldn't extend the support to
/// new opaque types in between changes to the SDK.
use mls_rs::crypto::SignaturePublicKey;
use mls_rs::crypto::SignatureSecretKey;

#[derive(Debug)]
pub struct SignatureKeypair {
    secret: SignatureSecretKey,
    public: SignaturePublicKey,
}
// add rng: Option<[u8; 32]>
pub fn mls_generate_signature_keypair(cs: CipherSuite) -> Result<SignatureKeypair, MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cipher_suite = crypto_provider.cipher_suite_provider(cs).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    Ok(SignatureKeypair { secret, public })
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

// Add rng: Option<[u8; 32]>
pub async fn generate_key_package(
    group_config: GroupConfig,
    signature_keypair: SignatureKeypair,
    randomness: Option<Vec<u8>>,
) -> Result<KeyPackage, MlsError> {
    unimplemented!()
    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/client.rs#L430
}

///
/// Validate a KeyPackage.
///
/// We could internalize the KeyPackage validation in the Group operations.

// TODO: Might need to pass the GroupConfig here as well.
pub fn validate_key_package(key_package: KeyPackage) -> Result<(), MlsError> {
    unimplemented!()
    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/external_client.rs#L104
}

///
/// Extract Signing Identity from a KeyPackage.
///

// TODO: Discuss if it shouldn't return a SignaturePublicKey instead.

pub fn signing_identity_from_key_package(
    key_package: KeyPackage,
) -> Result<SignaturePublicKey, MlsError> {
    unimplemented!()
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
    v: Version,
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
/// Get group members.
///
pub struct Identity {} // "google.com@groupId@clientId" <-> SigningIdentity
pub struct Epoch {} // u32

pub fn mls_members(gid: GroupId) -> Result<(Epoch, Vec<Identity>, Vec<SigningIdentity>), MlsError> {
    unimplemented!()
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

pub fn generate_group_id() -> Vec<u8> {
    unimplemented!()
}

pub fn mls_create_group(
    group_config: Option<GroupConfig>,
    gid: Option<GroupId>,
    myself: SigningIdentity,
    myself_sigkey: SignatureSecretKey,
    // psk: Option<Vec<u8>>, // See if we pass that here or in all Group operations
) -> Result<(GroupId, GroupState), MlsError> {
    // Set the cryptography provider
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();

    // // Load the Signature Secret Key
    // let secret_key = mls_rs_crypto_openssl::x509::signature_secret_key_from_bytes(include_bytes!(
    //     "./test_data/x509/leaf/key.pem"
    // ))
    // .unwrap();

    // Retrieve the ciphersuite from the Group Config
    let group_config = group_config.unwrap();
    let cs = Ok(group_config.ciphersuite)?;

    // Build the client
    let client = mls_rs::Client::builder()
        .crypto_provider(crypto_provider)
        .identity_provider(
            mls_rs_crypto_openssl::x509::identity_provider_from_certificate(include_bytes!(
                "./test_data/x509/root_ca/cert.der"
            ))
            .unwrap(),
        )
        .signing_identity(myself, myself_sigkey, cs)
        .build();

    // Generate a GroupId if none is provided
    let gid = match gid {
        Some(gid) => gid,
        None => generate_group_id(),
    };

    // Create a group context extension if none is provided
    let gce = match Some(group_config.options) {
        Some(gce) => gce,
        None => ExtensionList::new(),
    };

    // Create the group
    let mut group = client
        .create_group_with_id(gid.clone(), gce)
        .expect("Failed to create group");

    // The state needs to be returned or stored somewhere
    group.commit(Vec::new()).unwrap();
    group.apply_pending_commit().unwrap();

    Ok(gid)

    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/client.rs#L479
    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/group/mod.rs#L276
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

pub type MlsMessage = Vec<u8>;

pub fn mls_add_user(
    gid: GroupId,
    user: KeyPackage,
    myIdentity: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

pub fn mls_propose_add_user(
    gid: GroupId,
    user: KeyPackage,
    myIdentity: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

///
/// Group management: Removing a user.
///

// We can't really use the KeyPackage to remove a user.
// We need to use the identity of the user to remove them.

pub fn mls_rem_user(
    gid: GroupId,
    user: Identity,
    myIdentity: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

pub fn mls_propose_rem_user(
    gid: GroupId,
    user: Identity,
    myIdentity: SigningIdentity,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

///
/// Key updates
///
/// Note: Everyone is able to propose and commit to their key update.
///

/// Should we rename that commit ?
/// Possibly add a random nonce as an optional parameter.
pub fn mls_update(gid: GroupId, rng: Option<[u8; 32]>) -> Result<MlsMessage, MlsError> {
    // Propose + Commit
    unimplemented!()
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

fn mls_process_received_message(
    gid: GroupId,
    key_package: KeyPackage,
    message: MlsMessage,
) -> Result<(String), MlsError> {
    unimplemented!()

    // Internally the GroupState is updated.
}

// https://docs.rs/mls-rs/latest/mls_rs/group/mls_rules/trait.MlsRules.html#tymethod.filter_proposals

///
/// Process Welcome message.
///
/// Note: A Welcome will be processed to create a group object
/// for the invited member.
///

pub struct RatchetTree {}

fn mls_process_received_join_message(
    gid: GroupId,
    message: MlsMessage,
    ratchet_tree: Option<RatchetTree>,
) -> Result<(), MlsError> {
    // Internally the GroupState is updated.
    unimplemented!()
}

pub struct ProposalType; //u16

pub fn mls_send_custom_proposal(
    proposal_type: ProposalType,
    data: Vec<u8>,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

pub struct GroupContextExtensionType; //u16

pub fn mls_send_custom_groupcontextextension(
    gce_type: GroupContextExtensionType,
    data: Vec<u8>,
) -> Result<MlsMessage, MlsError> {
    unimplemented!()
}

// To leave the group
pub fn mls_leave(gid: GroupId, my_key_package: KeyPackage) -> Result<(), MlsError> {
    // Leave and zero out all the states: RemoveProposal
    unimplemented!()
}

// To close a group i.e., removing all members of the group.
fn mls_close(gid: GroupId) -> Result<bool, MlsError> {
    // Remove everyone from the group.
    unimplemented!()
}

//
// Encrypt a message.
//

pub fn mls_encrypt_message(
    gid: GroupId,
    my_key_package: KeyPackage,
    message: String,
) -> Result<MlsMessage, MlsError> {
    // Internally the GroupState is updated.
    unimplemented!()
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
    gid: GroupId,
    my_key_package: KeyPackage,
    label: String,
    epoch_number: Option<u32>,
) -> Result<(Vec<u8>, u32), MlsError> {
    // KDF of the secret of the current epoch.
    unimplemented!()
}

///
/// Import a group state into the storage
///
pub fn mls_import_group_state(
    group_state: Vec<u8>,
    signature_key: SignatureKeypair,
    my_key_package: KeyPackage,
) -> Result<(), MlsError> {
    unimplemented!()
    // https://github.com/awslabs/mls-rs/blob/main/mls-rs/src/client.rs#L605
}

pub fn mls_export_group_state(gid: GroupId) -> Result<PublicGroupState, MlsError> {
    unimplemented!()
}
