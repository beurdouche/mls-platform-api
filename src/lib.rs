use mls_rs::{CipherSuiteProvider, CryptoProvider};

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
    options: Vec<GroupContextExtensions>,
}

use mls_rs::crypto::SignaturePublicKey;
use mls_rs::crypto::SignatureSecretKey;

#[derive(Debug)]
pub struct KeyPackage {
    kp: mls_rs::KeyPackage,
}

#[derive(Debug)]
pub struct MlsError {
    error: mls_rs::error::MlsError,
}

/// Generate Signature Key Pair
///
/// - Option: default to Basic Credentials
/// - Possibly use strings as the credential types have names
/// - (Alternatively we could use integers)
///
/// If we were to use enums we couldn't extend the support to new opaque types in between changes to the SDK.

#[derive(Debug)]
pub struct SignatureKeypair {
    secret: SignatureSecretKey,
    public: SignaturePublicKey,
}

pub fn mls_generate_signature_keypair(cs: CipherSuite) -> Result<SignatureKeypair, MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cipher_suite = crypto_provider.cipher_suite_provider(cs).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    Ok(SignatureKeypair { secret, public })
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

pub fn generate_key_package(
    group_config: GroupConfig,
    signature_keypair: SignatureKeypair,
) -> Result<KeyPackage, MlsError> {
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

fn mls_create_group_config(
    cs: CipherSuite,
    v: Version,
    options: Vec<GroupContextExtensions>,
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

fn mls_create_client_config(
    max_past_epoch: Option<u32>,
    use_ratchet_tree_extension: bool,
    out_of_order_tolerance: Option<u32>,
    maximum_forward_distance: Option<u32>,
) -> Result<ClientConfig, MlsError> {
    unimplemented!()
}

/// To create a group for one person.
///
/// Note: the groupState is kept track of by the lib and is not returned to the app. If at some point the app needs to get the MlsState, we'll support a getMlsState(GroupId) function.
///
/// Note: this function underneath will write down the GroupState in its persistent storage.

pub type GroupId = Vec<u8>;

fn mls_create_group(
    group_config: Option<GroupConfig>,
    gid: Option<GroupId>,
    self_: KeyPackage,
    psk: Option<Vec<u8>>,
) -> Result<GroupId, MlsError> {
    unimplemented!()
}

/*
Group management: Adding a user.

Two cases depending on access control from the app:

Case 1: the proposer can commit.
Case 2: the proposer cannot commit, they can only propose.

The application should be able to decide this based on their access control either on client side or server side (eg the user X doesn't have permission to approve add requests to a groupID).

*/

// For Case 1:
// fn mls_add_user(
//     gid: GroupId,
//     user: KeyPackage,
//     myKeyPackage: KeyPackage
//     ) -> Result<Message, MLSError> {
//         unimplemented!()

//     }

//     // For Case 2:
//     fn mls_propose_add_user(
//     gid: GroupId,
//     user: KeyPackage,
//     myKeyPackage: KeyPackage
//     ) -> Result<Message, MLSError> {
//         unimplemented!()

//     }

// For removing users, the API is the same as for adding.

// For Case 1:
// fn mls_rem_user(
// gid: GroupId,
// user: KeyPackage
// ) -> Result<Message, MLSError> {
//     unimplemented!()

// }

// // For Case 2:
// fn mls_propose_rem_user(
// gid: GroupId,
// user: KeyPackage
// ) -> Result<Message, MLSError> {
//     unimplemented!()

// }

// Key updates - everyone is able to propose and commit to their key update.

// fn mls_update(gid: GroupId) -> Result<Message, MLSError> {
//     // Propose + Commit
//     unimplemented!()

// }

/*
Process a non-Welcome message from the app.

Note: when the higher level APIs (e.g., Java in case of Android) receives a message, it checks with the apps via callbacks whether the apps want to proceed with the message (e.g., if the message is a Commit, the app might not want to apply it due to ACL). That means the moment a message is passed down to this Rust layer, it'll be processed as prescribed by MLS:
A Proposal will result in a Commit.
A Commit will result in it being applied to advance the group state.
An application message will result in it being decrypted.
*/

// fn mls_process_received_message(gid: GroupId,keyPackage:KeyPackage, message: Message)
//  -> Result<(String), MLSError> {
//     unimplemented!()

// // Internally the GroupState is updated.
// }

//
// Process Welcome message from the app: A Welcome will be processed to create a group object for the invited member.
//

// fn mls_process_received_join_message(gid: GroupId, message: Message, ratchetTree:Option<RatchetTree>) -> Result<(), MLSError> {

//     // Internally the GroupState is updated.
//     unimplemented!()

//     }

//
// Encrypt a message.
//

// fn mls_encrypt_message(gid: GroupId, myKeyPackage:KeyPackage, message: String) -> Result<Message, MLSError> {
//     // Internally the GroupState is updated.
//     unimplemented!()

//     }

//     // To leave the group
// fn mls_leave(gid: GroupId, myKeyPackage:KeyPackage) -> Result<(), MLSError> {
//     // Leave and zero out all the states: RemoveProposal
//     unimplemented!()

// }

// fn mls_export(gid: GroupId, myKeyPackage:KeyPackage, label: String, epochNumber:Option<u32>) -> Result<(Exporter, u32),  MLSError> {
//     // KDF of the secret of the current epoch.
//     unimplemented!()

// }

// // To close a group i.e., removing all members of the group.
// fn mls_close(gid: GroupId) -> Result<bool, MLSError> {
//     // Remove everyone from the group.
//     unimplemented!()

// }

// // Get members of a group
// fn mls_get_members(gid: GroupId)
// -> Result<(Vec<Identifier>, Vec<KeyPackage>), MLSError> {
//     unimplemented!()

// }

// // With PublicGroupState + signatureKey + HPKE key one can rebuild the entire group state.
// fn mls_get_group_states(gid:GroupID) -> Result<PublicGroupState, MLSError> {
//     unimplemented!()
// }
