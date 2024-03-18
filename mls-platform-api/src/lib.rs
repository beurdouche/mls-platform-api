// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod state;

use mls_rs::error::{AnyError, IntoAnyError};
use mls_rs::group::proposal::{CustomProposal, ProposalType};
use mls_rs::group::{Capabilities, ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::{CipherSuiteProvider, CryptoProvider, Extension, ExtensionList};

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use state::{PlatformState, TemporaryState};
use std::fmt;

pub type DefaultCryptoProvider = mls_rs_crypto_nss::NssCryptoProvider;
pub type DefaultIdentityProvider = mls_rs::identity::basic::BasicIdentityProvider;

// Re-export the mls_rs types
pub use mls_rs::CipherSuite;
pub use mls_rs::MlsMessage;
pub use mls_rs::ProtocolVersion;

// Define new types
pub type GroupId = Vec<u8>;
pub type GroupState = Vec<u8>;
pub type Identity = Vec<u8>;
pub type GroupEpoch = u64;
pub type Credential = Vec<u8>;

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
    #[error("CoreError")]
    CoreError,
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
    #[error("JsonConversionError")]
    JsonConversionError,
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
pub fn state_access(name: String, key: [u8; 32]) -> Result<PlatformState, PlatformError> {
    PlatformState::new(name, key)
}

///
/// Delete a PlatformState.
///
pub fn state_delete(name: String) -> Result<(), PlatformError> {
    PlatformState::delete(name)
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
pub fn mls_generate_credential_basic(name: &str) -> Result<Credential, PlatformError> {
    let credential =
        mls_rs::identity::basic::BasicCredential::new(name.as_bytes().to_vec()).into_credential();
    let credential_bytes = credential.mls_encode_to_vec()?;
    Ok(credential_bytes)
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
    let _ = state.insert_sigkey(&signature_key, &signature_pubkey, cs, &identifier);

    Ok(identifier)
}

///
/// Generate a KeyPackage.
///
pub fn mls_generate_key_package(
    state: &PlatformState,
    myself: Identity,
    credential: Credential,
    // Below is client config
    key_package_extensions: Option<ExtensionList>,
    leaf_node_extensions: Option<ExtensionList>,
    leaf_node_capabilities: Option<Capabilities>,
    _lifetime: Option<u64>,
    // _randomness: Option<Vec<u8>>,
) -> Result<MlsMessage, PlatformError> {
    // Decode the Credential
    let decoded_cred = mls_rs::identity::Credential::mls_decode(&mut credential.as_slice())?;

    // Create a client for that state
    let client = state.client(
        &myself,
        Some(decoded_cred),
        ProtocolVersion::MLS_10,
        key_package_extensions,
        leaf_node_extensions,
        None,
        leaf_node_capabilities,
    )?;

    // Generate a KeyPackage from that client_default
    let key_package = client.generate_key_package_message()?;

    // TODO: We should store the key packages in the state
    // let kp_bytes = key_package.mls_encode_to_vec()?;
    Ok(key_package)
}

///
/// Get group members.
///

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MlsMembers {
    epoch: u64,
    identities: Vec<(Identity, Credential)>,
}

pub type MlsMembersJsonBytes = Vec<u8>;

// Note: The identity is needed because it is allowed to have multiple
//       identities in a group.
pub fn mls_members(
    state: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
) -> Result<MlsMembersJsonBytes, PlatformError> {
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
                identity.credential.mls_encode_to_vec()?,
            ))
        })
        .collect::<Result<Vec<_>, PlatformError>>()?;

    let members = MlsMembers { epoch, identities };

    // Encode the message as Json Bytes
    let members_json_string =
        serde_json::to_string(&members).map_err(|_| PlatformError::JsonConversionError)?;
    let members_json_bytes = members_json_string.as_bytes().to_vec();

    Ok(members_json_bytes)
}

///
/// Group management: Create a Group
///

// TODO: We internally set the protocol version to avoid issues with

pub fn mls_group_create(
    pstate: &mut PlatformState,
    myself: &Identity,
    credential: Credential,
    gid: Option<GroupId>,
    // Client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    _leaf_node_capabilities: Option<Capabilities>,
    _lifetime: Option<u64>,
) -> Result<GroupId, PlatformError> {
    // Build the client
    let decoded_cred = mls_rs::identity::Credential::mls_decode(&mut credential.as_slice())?;

    let client = pstate.client(
        myself,
        Some(decoded_cred),
        ProtocolVersion::MLS_10,
        None,
        None,
        None,
        None,
    )?;

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

#[derive(Clone, Debug, PartialEq)]
pub struct MlsCommitOutput {
    pub commit: MlsMessage,
    pub welcome: Vec<MlsMessage>,
    pub group_info: Option<MlsMessage>,
    pub ratchet_tree: Option<Vec<u8>>,
    // pub unused_proposals: Vec<crate::mls_rules::ProposalInfo<Proposal>>, from mls_rs
}

impl Serialize for MlsCommitOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MlsCommitOutput", 4)?;

        // Handle serialization for `commit`
        let commit_bytes = self
            .commit
            .mls_encode_to_vec()
            .map_err(serde::ser::Error::custom)?;
        state.serialize_field("commit", &commit_bytes)?;

        // Handle serialization for `welcome`. Collect into a Result to handle potential errors.
        let welcome_bytes: Result<Vec<_>, _> = self
            .welcome
            .iter()
            .map(|msg| msg.mls_encode_to_vec().map_err(serde::ser::Error::custom))
            .collect();
        // Unwrap the Result here, after all potential errors have been handled.
        state.serialize_field("welcome", &welcome_bytes?)?;

        // Handle serialization for `group_info`
        let group_info_bytes = match self.group_info.as_ref().map(|gi| gi.mls_encode_to_vec()) {
            Some(Ok(bytes)) => Some(bytes),
            Some(Err(e)) => return Err(serde::ser::Error::custom(e)),
            None => None,
        };
        state.serialize_field("group_info", &group_info_bytes)?;

        // Directly serialize `ratchet_tree` as it is already an Option<Vec<u8>>
        state.serialize_field("ratchet_tree", &self.ratchet_tree)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for MlsCommitOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MlsCommitOutputVisitor;

        impl<'de> Visitor<'de> for MlsCommitOutputVisitor {
            type Value = MlsCommitOutput;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct MlsCommitOutput")
            }

            fn visit_map<V>(self, mut map: V) -> Result<MlsCommitOutput, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut commit = None;
                let mut welcome = None;
                let mut group_info = None;
                let mut ratchet_tree = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "commit" => {
                            let value: Vec<u8> = map.next_value()?;
                            commit = Some(
                                MlsMessage::mls_decode(&mut &value[..])
                                    .map_err(de::Error::custom)?,
                            );
                        }
                        "welcome" => {
                            let values: Vec<Vec<u8>> = map.next_value()?;
                            welcome = Some(
                                values
                                    .into_iter()
                                    .map(|v| {
                                        MlsMessage::mls_decode(&mut &v[..])
                                            .map_err(de::Error::custom)
                                    })
                                    .collect::<Result<_, _>>()?,
                            );
                        }
                        "group_info" => {
                            if let Some(value) = map.next_value::<Option<Vec<u8>>>()? {
                                group_info = Some(
                                    MlsMessage::mls_decode(&mut &value[..])
                                        .map_err(de::Error::custom)?,
                                );
                            }
                        }
                        "ratchet_tree" => {
                            ratchet_tree = map.next_value()?;
                        }
                        _ => { /* Ignore unknown fields */ }
                    }
                }

                Ok(MlsCommitOutput {
                    commit: commit.ok_or_else(|| de::Error::missing_field("commit"))?,
                    welcome: welcome.ok_or_else(|| de::Error::missing_field("welcome"))?,
                    group_info,
                    ratchet_tree,
                })
            }
        }

        const FIELDS: &'static [&'static str] =
            &["commit", "welcome", "group_info", "ratchet_tree"];
        deserializer.deserialize_struct("MlsCommitOutput", FIELDS, MlsCommitOutputVisitor)
    }
}

pub type MlsCommitOutputJsonBytes = Vec<u8>;

pub fn mls_group_add(
    pstate: &mut PlatformState,
    gid: &GroupId,
    myself: &Identity,
    new_members: Vec<MlsMessage>,
) -> Result<MlsCommitOutputJsonBytes, PlatformError> {
    // Get the group from the state
    let client = pstate.client_default(myself)?;
    let mut group = client.load_group(gid)?;

    let commit_output = new_members
        .into_iter()
        .try_fold(group.commit_builder(), |commit_builder, user| {
            commit_builder.add_member(user)
        })?
        .build()?;

    // We use the default mode which returns only one welcome message
    let welcomes = commit_output.welcome_messages; //.remove(0);

    let commit_output = MlsCommitOutput {
        commit: commit_output.commit_message.clone(),
        welcome: welcomes,
        group_info: commit_output.external_commit_group_info,
        ratchet_tree: None, // TODO: Handle this !
    };

    // Write the group to the storage
    group.write_to_storage()?;

    // Encode the message as Json Bytes
    let js_string =
        serde_json::to_string(&commit_output).map_err(|_| PlatformError::JsonConversionError)?;
    let js_bytes = js_string.as_bytes().to_vec();

    Ok(js_bytes)
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
    gid: &GroupId,
    myself: &Identity,
    removed: &Identity, // TODO: Make this Vec<Identities>?
) -> Result<MlsCommitOutputJsonBytes, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(gid)?;

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
            (h == *removed).then_some(m.index)
        })
        .ok_or(PlatformError::UndefinedIdentity)?;

    let commit = group.commit_builder().remove_member(removed)?.build()?;

    // Write the group to the storage
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

    // Encode the message as Json Bytes
    let json_string =
        serde_json::to_string(&commit_output).map_err(|_| PlatformError::JsonConversionError)?;
    let json_bytes = json_string.as_bytes().to_vec();

    Ok(json_bytes)
}

pub fn mls_group_propose_remove(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    removed: &Identity, // TODO: Handle Vec<Identity>
) -> Result<MlsMessage, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(gid)?;

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
            (h == *removed).then_some(m.index)
        })
        .ok_or(PlatformError::UndefinedIdentity)?;

    let proposal = group.propose_remove(removed, vec![])?;
    Ok(proposal)
}

///
/// Key updates
///

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MlsGroupUpdate {
    identity: Identity,
    commit_output: MlsCommitOutput,
}

pub type MlsGroupUpdateJsonBytes = Vec<u8>;

/// TODO: Possibly add a random nonce as an optional parameter.
pub fn mls_group_update(
    pstate: &mut PlatformState,
    gid: GroupId,
    myself: Identity,
    signature_key: Option<Vec<u8>>,
    credential: Option<Credential>,
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    _leaf_node_capabilities: Option<Capabilities>,
    _lifetime: Option<u64>,
) -> Result<MlsGroupUpdateJsonBytes, PlatformError> {
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

        let decoded_cred = mls_rs::identity::Credential::mls_decode(&mut cred.as_slice())?;

        let signing_identity = SigningIdentity::new(decoded_cred, signature_public_key);
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

    // Encode the message as Json Bytes
    let json_string =
        serde_json::to_string(&group_update).map_err(|_| PlatformError::JsonConversionError)?;
    let json_bytes = json_string.as_bytes().to_vec();

    Ok(json_bytes)
}

pub fn mls_group_propose_update(
    _pstate: &mut PlatformState,
    _gid: GroupId,
    _myself: &Identity,
    _signature_key: Option<Vec<u8>>,
    // Below is client config
    _group_context_extensions: Option<ExtensionList>,
    _leaf_node_extensions: Option<ExtensionList>,
    _leaf_node_capabilities: Option<Capabilities>,
    _lifetime: Option<u64>,
) -> Result<MlsMessage, PlatformError> {
    unimplemented!()
}

///
/// Process Welcome message.
///

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
/// Close a group by removing all members.
///

// TODO: Define a custom proposal instead.
pub fn mls_group_close(
    pstate: PlatformState,
    gid: GroupId,
    myself: &Identity,
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
/// Receive a message
///

pub fn mls_receive(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    message_or_ack: MlsMessageOrAck,
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
) -> Result<MlsMessage, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(gid)?;

    let out = group.encrypt_application_message(message, vec![])?;
    group.write_to_storage()?;

    Ok(out)
}

///
/// Propose + Commit a GroupContextExtension
///
pub fn mls_send_group_context_extension(
    pstate: &PlatformState,
    gid: GroupId,
    myself: &Identity,
    new_gce: Vec<Extension>,
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
) -> Result<mls_rs::MlsMessage, PlatformError> {
    let mut group = pstate.client_default(myself)?.load_group(&gid)?;
    let custom_proposal = CustomProposal::new(proposal_type, data);
    let proposal = group.propose_custom(custom_proposal, vec![])?;

    Ok(proposal)
}

///
/// Export a group secret.
///

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MlsExporterOutput {
    epoch: u64,
    exporter: Vec<u8>,
}

pub type MlsExporterOutputJsonBytes = Vec<u8>;

pub fn mls_export(
    pstate: &PlatformState,
    gid: &GroupId,
    myself: &Identity,
    label: &[u8],
    context: &[u8],
    len: u64,
) -> Result<MlsExporterOutputJsonBytes, PlatformError> {
    let group = pstate.client_default(myself)?.load_group(gid)?;
    let secret = group
        .export_secret(label, context, len.try_into().unwrap())?
        .to_vec();

    // Construct the output object
    let epoch_and_exporter = MlsExporterOutput {
        epoch: group.current_epoch(),
        exporter: secret,
    };

    // Encode the value as Json Bytes
    let json_string = serde_json::to_string(&epoch_and_exporter)
        .map_err(|_| PlatformError::JsonConversionError)?;
    let json_bytes = json_string.as_bytes().to_vec();

    Ok(json_bytes)
}

///
/// Utility functions
///
use serde_json::{Error, Value};

// This function takes a JSON string and converts byte arrays into hex strings.
fn convert_bytes_fields_to_hex(input_str: &str) -> Result<String, Error> {
    // Parse the JSON string into a serde_json::Value
    let mut value: Value = serde_json::from_str(input_str)?;

    // Recursive function to process each element
    fn process_element(element: &mut Value) {
        match element {
            Value::Array(ref mut vec) => {
                if vec
                    .iter()
                    .all(|x| matches!(x, Value::Number(n) if n.is_u64()))
                {
                    // Convert all elements to a Vec<u8> if they are numbers
                    let bytes: Vec<u8> = vec
                        .iter()
                        .filter_map(|x| x.as_u64().map(|n| n as u8))
                        .collect();
                    // Check if the conversion makes sense (the length matches)
                    if bytes.len() == vec.len() {
                        *element = Value::String(hex::encode(bytes));
                    } else {
                        vec.iter_mut().for_each(process_element);
                    }
                } else {
                    vec.iter_mut().for_each(process_element);
                }
            }
            Value::Object(ref mut map) => {
                map.values_mut().for_each(process_element);
            }
            _ => {}
        }
    }
    // Process the element and return the new Json string
    process_element(&mut value);
    serde_json::to_string(&value)
}

// This function accepts bytes, converts them to a string, and then processes the string.
pub fn utils_json_bytes_to_string_custom(input_bytes: &[u8]) -> Result<String, PlatformError> {
    // Convert input bytes to a string
    let input_str =
        std::str::from_utf8(input_bytes).map_err(|_| PlatformError::JsonConversionError)?;

    // Call the original function with the decoded string
    convert_bytes_fields_to_hex(input_str).map_err(|_| PlatformError::JsonConversionError)
}
