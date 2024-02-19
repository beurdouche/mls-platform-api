#![allow(dead_code, unused_imports)]

use std::sync::{Arc, Mutex};

use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::basic::BasicIdentityProvider;
use mls_rs::identity::Credential;
use mls_rs::{CipherSuiteProvider, Client, CryptoProvider};
use mls_rs_core::identity::{BasicCredential, SigningIdentity};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
uniffi::ffi_converter_forward!(
    mls_rs::CipherSuite,
    mls_rs_core::UniFfiTag,
    crate::UniFfiTag
);

/// Unwrap the `Arc` if there is a single strong reference, otherwise
/// clone the inner value.
fn arc_unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    match Arc::try_unwrap(arc) {
        Ok(t) => t,
        Err(arc) => (*arc).clone(),
    }
}

#[derive(thiserror::Error, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[non_exhaustive]
pub enum LiteError {
    #[error("A mls-rs error occurred")]
    MlsError { inner: mls_rs::error::MlsError },
}

impl From<mls_rs::error::MlsError> for LiteError {
    fn from(inner: mls_rs::error::MlsError) -> Self {
        Self::MlsError { inner }
    }
}

/// A [`mls_rs::crypto::SignaturePublicKey`] wrapper.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteSignaturePublicKey {
    inner: mls_rs::crypto::SignaturePublicKey,
}

//impl From<mls_rs::crypto::SignaturePublicKey> for LiteSignaturePublicKey {
//    fn from(inner: mls_rs::crypto::SignaturePublicKey) -> Self {
//        Self { inner }
//    }
//}
//
//impl From<LiteSignaturePublicKey> for mls_rs::crypto::SignaturePublicKey {
//    fn from(public_key: LiteSignaturePublicKey) -> Self {
//        public_key.inner
//    }
//}

/// A [`mls_rs::crypto::SignatureSecretKey`] wrapper.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteSignatureSecretKey {
    inner: mls_rs::crypto::SignatureSecretKey,
}

//impl From<mls_rs::crypto::SignatureSecretKey> for LiteSignatureSecretKey {
//    fn from(inner: mls_rs::crypto::SignatureSecretKey) -> Self {
//        Self { inner }
//    }
//}
//
//impl From<LiteSignatureSecretKey> for mls_rs::crypto::SignatureSecretKey {
//    fn from(secret_key: LiteSignatureSecretKey) -> Self {
//        secret_key.inner
//    }
//}

/// A ([`SignaturePublicKey`], [`SignatureSecretKey`]) pair.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug)]
pub struct LiteSignatureKeypair {
    public_key: Arc<LiteSignaturePublicKey>,
    secret_key: Arc<LiteSignatureSecretKey>,
}

pub type LiteConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

/// Light-weight wrapper around a [`mls_rs::Group`] and a  [`mls_rs::group::NewMemberInfo`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone)]
pub struct LiteJoinInfo {
    /// The group that was joined.
    group: Arc<LiteGroup>,
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub group_info_extensions: Arc<mls_rs::ExtensionList>,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteKeyPackage {
    inner: mls_rs::KeyPackage,
}

/// Light-weight wrapper around a [`mls_rs::MlsMessage`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteMessage {
    inner: mls_rs::MlsMessage,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteProposal {
    inner: mls_rs::group::proposal::Proposal,
}

/// Light-weight wrapper around a [`mls_rs::group::ReceivedMessage`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug)]
pub enum LiteReceivedMessage {
    /// A decrypted application message.
    ApplicationMessage {
        sender: Arc<SigningIdentity>,
        data: Vec<u8>,
    },

    /// A new commit was processed creating a new group state.
    Commit { committer: Arc<SigningIdentity> },

    /// A proposal was received.
    Proposal {
        sender: Arc<SigningIdentity>,
        proposal: Arc<LiteProposal>,
    },

    /// Validated GroupInfo object.
    GroupInfo,
    /// Validated welcome message.
    Welcome,

    /// Validated key package.
    KeyPackage { key_package: Arc<LiteKeyPackage> },
}

/// Supported cipher suites.
///
/// This is a subset of the cipher suites found in
/// [`mls_rs::CipherSuite`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Copy, Clone, Debug)]
pub enum LiteCipherSuite {
    // TODO(mgeisler): fill out.
    Curve25519Aes128,
}

impl From<LiteCipherSuite> for mls_rs::CipherSuite {
    fn from(cipher_suite: LiteCipherSuite) -> mls_rs::CipherSuite {
        match cipher_suite {
            LiteCipherSuite::Curve25519Aes128 => mls_rs::CipherSuite::CURVE25519_AES128,
        }
    }
}

/// Generate a MLS signature keypair.
///
/// This will use the default mls-lite crypto provider.
///
/// See [`mls_rs::CipherSuiteProvider::signature_key_generate`]
/// for details.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_signature_keypair(
    cipher_suite: LiteCipherSuite,
) -> Result<LiteSignatureKeypair, LiteError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cipher_suite.into())
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite.into()))?;

    let (secret_key, public_key) = cipher_suite_provider
        .signature_key_generate()
        .map_err(|err| MlsError::CryptoProviderError(err.into_any_error()))?;

    Ok(LiteSignatureKeypair {
        public_key: Arc::new(LiteSignaturePublicKey { inner: public_key }),
        secret_key: Arc::new(LiteSignatureSecretKey { inner: secret_key }),
    })
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone, Debug)]
pub struct LiteClient {
    inner: mls_rs::client::Client<LiteConfig>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl LiteClient {
    /// Create a new client.
    ///
    /// The user is identified by `id`, which will be used to create a
    /// basic credential together with the signature keypair.
    ///
    /// See [`mls_rs::Client::builder`] for details.
    #[uniffi::constructor]
    pub fn new(
        id: Vec<u8>,
        signature_keypair: LiteSignatureKeypair,
        cipher_suite: LiteCipherSuite,
    ) -> Self {
        let public_key = arc_unwrap_or_clone(signature_keypair.public_key);
        let secret_key = arc_unwrap_or_clone(signature_keypair.secret_key);
        let crypto_provider = OpensslCryptoProvider::new();
        let basic_credential = BasicCredential::new(id);
        let signing_identity =
            SigningIdentity::new(basic_credential.into_credential(), public_key.inner);
        LiteClient {
            inner: Client::builder()
                .crypto_provider(crypto_provider)
                .identity_provider(BasicIdentityProvider::new())
                .signing_identity(signing_identity, secret_key.inner, cipher_suite.into())
                .build(),
        }
    }

    /// Generate a new key package for this client.
    ///
    /// The key package is represented in is MLS message form. It is
    /// needed when joining a group and can be published to a server
    /// so other clients can look it up.
    ///
    /// See [`mls_rs::Client::generate_key_package_message`] for
    /// details.
    pub fn generate_key_package_message(&self) -> Result<LiteMessage, LiteError> {
        let inner = self.inner.generate_key_package_message()?;
        Ok(LiteMessage { inner })
    }

    /// Create and immediately join a new group.
    ///
    /// If a group ID is not given, the underlying library will create
    /// a unique ID for you.
    ///
    /// See [`mls_rs::Client::create_group`] and
    /// [`mls_rs::Client::create_group_with_id`] for details.
    pub fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<LiteGroup, LiteError> {
        let extensions = mls_rs::ExtensionList::new();
        let inner = match group_id {
            Some(group_id) => self.inner.create_group_with_id(group_id, extensions)?,
            None => self.inner.create_group(extensions)?,
        };
        Ok(LiteGroup {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Join an existing group.
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub fn join_group(&self, welcome_message: Arc<LiteMessage>) -> Result<LiteJoinInfo, LiteError> {
        let welcome_message = arc_unwrap_or_clone(welcome_message);
        let (group, new_member_info) = self.inner.join_group(None, welcome_message.inner)?;

        let group = Arc::new(LiteGroup {
            inner: Arc::new(Mutex::new(group)),
        });
        let group_info_extensions = Arc::new(new_member_info.group_info_extensions);
        Ok(LiteJoinInfo {
            group,
            group_info_extensions,
        })
    }
}

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone)]
pub struct LiteGroup {
    inner: Arc<Mutex<mls_rs::Group<LiteConfig>>>,
}

impl LiteGroup {
    fn inner(&self) -> std::sync::MutexGuard<'_, mls_rs::Group<LiteConfig>> {
        self.inner.lock().unwrap()
    }

    fn index_to_identity(&self, index: u32) -> Result<SigningIdentity, LiteError> {
        let group = self.inner();
        let member = group
            .member_at_index(index)
            .ok_or(MlsError::InvalidNodeIndex(index))?;
        Ok(member.signing_identity)
    }
}

/// Extract the basic credential identifier from a  from a key package.
fn signing_identity_to_identifier(
    signing_identity: &SigningIdentity,
) -> Result<Vec<u8>, mls_rs::error::MlsError> {
    match &signing_identity.credential {
        Credential::Basic(credential) => Ok(credential.identifier.clone()),
        _ => Err(MlsError::RequiredCredentialNotFound(
            BasicCredential::credential_type(),
        )),
    }
}

/// Extract the basic credential identifier from a key package.
fn key_package_into_identifier(message: mls_rs::MlsMessage) -> Result<Vec<u8>, LiteError> {
    let key_package = message
        .into_key_package()
        .ok_or(MlsError::UnexpectedMessageType)?;
    let signing_identity = key_package.signing_identity();
    let Credential::Basic(credential) = &signing_identity.credential else {
        return Err(
            MlsError::RequiredCredentialNotFound(BasicCredential::credential_type()).into(),
        );
    };

    Ok(credential.identifier.clone())
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl LiteGroup {
    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// See [`mls_rs::Group::commit`] for details.
    pub fn commit(&self) -> Result<mls_rs::group::CommitOutput, LiteError> {
        let commit_output = self.inner().commit(Vec::new())?;
        Ok(commit_output)
    }

    /// Commit the addition of a member.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::group::CommitBuilder::add_member`] for details.
    pub fn add_member(
        &self,
        member: Arc<LiteMessage>,
    ) -> Result<mls_rs::group::CommitOutput, LiteError> {
        let member = arc_unwrap_or_clone(member);
        let commit_output = self
            .inner()
            .commit_builder()
            .add_member(member.inner)?
            .build()?;
        Ok(commit_output)
    }

    /// Propose to add a member to this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::Group::propose_add`] for details.
    pub fn propose_add_member(&self, member: Arc<LiteMessage>) -> Result<LiteMessage, LiteError> {
        let member = arc_unwrap_or_clone(member);
        let mut group = self.inner();
        let inner = group.propose_add(member.inner, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Propose and commit the removal of a member.
    ///
    /// The member is representated by the key package in `member`.
    ///
    /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    pub fn remove_member(
        &self,
        member: Arc<SigningIdentity>,
    ) -> Result<mls_rs::group::CommitOutput, LiteError> {
        let identifier = signing_identity_to_identifier(&member)?;
        let mut group = self.inner();
        let member = group.member_with_identity(&identifier)?;
        let commit_output = group
            .commit_builder()
            .remove_member(member.index)?
            .build()?;
        Ok(commit_output)
    }

    /// Propose to remove a member from this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::group::Group::propose_remove`] for details.
    pub fn propose_remove_member(
        &self,
        member: Arc<LiteMessage>,
    ) -> Result<LiteMessage, LiteError> {
        let member = arc_unwrap_or_clone(member);
        let identifier = key_package_into_identifier(member.inner)?;
        let mut group = self.inner();
        let member = group.member_with_identity(&identifier)?;
        let inner = group.propose_remove(member.index, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Encrypt an application message using the current group state.
    pub fn encrypt_application_message(&self, message: &[u8]) -> Result<LiteMessage, LiteError> {
        let mut group = self.inner();
        let inner = group.encrypt_application_message(message, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Process an inbound message for this group.
    ///
    /// # Warning
    ///
    /// Changes to the group’s state as a result of processing message
    /// will not be persisted until [`LiteGroup::write_to_storage`] is
    /// called.
    pub fn process_incoming_message(
        &self,
        message: Arc<LiteMessage>,
    ) -> Result<LiteReceivedMessage, LiteError> {
        let message = arc_unwrap_or_clone(message);
        let mut group = self.inner();
        match group.process_incoming_message(message.inner)? {
            ReceivedMessage::ApplicationMessage(application_message) => {
                let sender = Arc::new(self.index_to_identity(application_message.sender_index)?);
                let data = application_message.authenticated_data;
                Ok(LiteReceivedMessage::ApplicationMessage { sender, data })
            }
            ReceivedMessage::Commit(commit_message) => {
                let committer = Arc::new(self.index_to_identity(commit_message.committer)?);
                Ok(LiteReceivedMessage::Commit { committer })
            }
            ReceivedMessage::Proposal(proposal_message) => {
                let sender = match proposal_message.sender {
                    mls_rs::group::ProposalSender::Member(index) => {
                        Arc::new(self.index_to_identity(index)?)
                    }
                    _ => todo!("External and NewMember proposal senders are not supported"),
                };
                let proposal = Arc::new(LiteProposal {
                    inner: proposal_message.proposal,
                });
                Ok(LiteReceivedMessage::Proposal { sender, proposal })
            }
            // TODO: ReceivedMessage::GroupInfo does not have any
            // public methods (unless the "ffi" Cargo feature is set).
            // So perhaps we don't need it?
            ReceivedMessage::GroupInfo(_) => Ok(LiteReceivedMessage::GroupInfo),
            ReceivedMessage::Welcome => Ok(LiteReceivedMessage::Welcome),
            ReceivedMessage::KeyPackage(inner) => {
                let key_package = Arc::new(LiteKeyPackage { inner });
                Ok(LiteReceivedMessage::KeyPackage { key_package })
            }
        }
    }

    /// Apply a pending commit.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn apply_pending_commit(&self) -> Result<(), MlsError> {
        self.inner().apply_pending_commit()?;
        Ok(())
    }
}
