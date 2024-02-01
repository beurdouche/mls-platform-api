mod state;

use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rs_codec::MlsEncode;
// use mls_rs::storage_provider::GroupState;
use mls_rs::{
    group, CipherSuiteProvider, CryptoProvider, ExtensionList, KeyPackageStorage, ProtocolVersion,
};

///
/// Errors
///
#[derive(Debug)]
pub struct MlsError {
    error: mls_rs::error::MlsError,
}

impl From<mls_rs::error::MlsError> for MlsError {
    fn from(error: mls_rs::error::MlsError) -> Self {
        Self { error }
    }
}

///
/// Generate a State.
///
pub fn create_state() -> State {
    State::new().unwrap()
}

// Definition of the GroupContext Extensions
#[derive(Debug)]
pub struct GroupContextExtensions {
    // Add fields as needed
}

// Definition of the type for the CipherSuite
pub use mls_rs::CipherSuite;

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

// Stateless function
fn mls_stateless_generate_signature_keypair(
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<(SigningIdentity, SignatureSecretKey), MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
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
    state: &mut State,
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<SigningIdentity, MlsError> {
    // Generate the signature key pair and the siging identity.
    let (signing_identity, signing_key) =
        mls_stateless_generate_signature_keypair(name, cs, _randomness)?;

    // Store the signature key pair.
    state.sigkeys.insert(
        signing_identity.mls_encode_to_vec().unwrap(),
        SignatureData {
            cs: *cs,
            secret_key: signing_key.to_vec(),
        },
    );
    Ok(signing_identity)
}

///
/// Generate a credential.
///
use mls_rs::identity::basic::BasicCredential;
use sha2::digest::crypto_common::Key;
use sha2::{Digest, Sha256};
use state::{KeyPackageData2, SignatureData, State};

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

#[derive(Debug)]
pub struct KeyPackage {
    kp: mls_rs::KeyPackage,
}

fn mls_stateless_generate_key_package(
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
    myself_sigkey: SignatureSecretKey,
    _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();

    // Match the ciphersuite
    // TODO: replace this by creating a default GroupConfig value
    let cs = match group_config {
        Some(c) => c.ciphersuite,
        None => {
            //MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            CipherSuite::CURVE25519_AES128
        }
    };
    let cipher_suite = crypto_provider.cipher_suite_provider(cs).unwrap();

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

    // Generate a KeyPackage
    let key_package = client.generate_key_package_message()?;
    Ok(key_package.to_bytes()?)
}

// Add rng: Option<[u8; 32]>
pub fn generate_key_package(
    state: &State,
    myself: SigningIdentity,
    group_config: Option<GroupConfig>,
    _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, MlsError> {
    // Create an artificial copy of the state
    let state_clone = state.clone();

    // Create a client for that artificial state
    let client = state_clone.client(myself, group_config.clone())?;

    // Generate a KeyPackage from that Client
    let key_package = client.generate_key_package_message()?;
    let key_package_bytes = key_package.to_bytes()?;

    // Calculate the SHA256 hash of the key package
    let mut hasher = Sha256::new();
    hasher.update(&key_package_bytes);
    let id = hasher.finalize();

    let kp = KeyPackage {
        kp: Ok::<std::option::Option<mls_rs::KeyPackage>, MlsError>(
            key_package.into_key_package(),
        )?
        .expect("KeyPackage"),
    };

    let kp_data = unimplemented!();

    // Insert the Key Package in the * real * state
    state.insert(id.to_vec(), kp_data);

    Ok(key_package.to_bytes()?)
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

// TODO: Secure erasure
pub fn generate_group_id(n: usize) -> Vec<u8> {
    let mut r: Vec<u8> = vec![0; n]; // Assuming you want a 16-byte ID, adjust the size as needed
    mls_rs_crypto_openssl::openssl::rand::rand_bytes(&mut r).unwrap();
    r
}

pub fn mls_create_group(
    state: &mut State,
    group_config: Option<GroupConfig>,
    gid: Option<GroupId>,
    myself: SigningIdentity,
    // psk: Option<Vec<u8>>, // See if we pass that here or in all Group operations
) -> Result<GroupId, MlsError> {
    // Set the cryptography provider

    // // Load the Signature Secret Key
    // let secret_key = mls_rs_crypto_openssl::x509::signature_secret_key_from_bytes(include_bytes!(
    //     "./test_data/x509/leaf/key.pem"
    // ))
    // .unwrap();

    // Retrieve the ciphersuite from the Group Config
    //let group_config = group_config.unwrap();
    //let cs = group_config.ciphersuite.into();
    //let storage = State::new(3, &myself, &myself_sigkey, cs).unwrap();

    // Build the client
    let client = state.client(myself, group_config.clone())?;

    // Generate a GroupId if none is provided
    let gid = match gid {
        Some(gid) => gid,
        None => generate_group_id(32),
    };

    // Create a group context extension if none is provided
    let gce = match group_config {
        Some(c) => c.options,
        None => ExtensionList::new(),
    };

    // Create the group
    let mut group = client.create_group_with_id(gid.clone(), gce)?;

    group.commit(Vec::new())?;
    group.apply_pending_commit()?;

    // The state needs to be returned or stored somewhere
    group.write_to_storage()?;
    let gid = group.group_id().to_vec();
    //let state = storage.to_bytes().unwrap();
    //let group_state_tree = group.export_tree().unwrap();

    // Return
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
    myself: SigningIdentity,
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
pub fn mls_update(
    gid: GroupId,
    state: &mut State,
    myself: SigningIdentity,
    rng: Option<[u8; 32]>,
) -> Result<MlsMessage, MlsError> {
    // Propose + Commit
    let client = state.client(myself, None)?;
    let mut group = client.load_group(&gid)?;
    let commit = group.commit(vec![])?;

    group.write_to_storage()?;

    Ok(commit.commit_message.to_bytes()?)
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
