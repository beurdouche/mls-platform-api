#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
use mls_rs::error::{IntoAnyError, MlsError};
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

/// A ([`mls_rs::crypto::SignaturePublicKey`],
/// [`mls_rs::crypto::SignatureSecretKey`]) pair.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SignatureKeypair {
    public_key: Arc<mls_rs::crypto::SignaturePublicKey>,
    secret_key: Arc<mls_rs::crypto::SignatureSecretKey>,
}

pub type LiteConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

/// Light-weight wrapper around a [`mls_rs::group::NewMemberInfo`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteNewMemberInfo {
    inner: mls_rs::group::NewMemberInfo,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteKeyPackage {
    inner: mls_rs::KeyPackage,
}

/// Light-weight wrapper around a [`mls_rs::MlsMessage`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteMessage {
    inner: mls_rs::MlsMessage,
}

impl LiteMessage {
    /// Convert a message into a key package.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn into_key_package(self) -> Option<mls_rs::KeyPackage> {
        self.inner.into_key_package()
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
    cipher_suite: mls_rs::CipherSuite,
) -> Result<SignatureKeypair, MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cipher_suite)
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite))?;

    let (secret_key, public_key) = cipher_suite_provider
        .signature_key_generate()
        .map_err(|err| MlsError::CryptoProviderError(err.into_any_error()))?;

    Ok(SignatureKeypair {
        public_key: Arc::new(public_key),
        secret_key: Arc::new(secret_key),
    })
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteClient {
    inner: mls_rs::client::Client<LiteConfig>,
}

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
        signature_keypair: SignatureKeypair,
        cipher_suite: mls_rs::CipherSuite,
    ) -> Self {
        let public_key = arc_unwrap_or_clone(signature_keypair.public_key);
        let secret_key = arc_unwrap_or_clone(signature_keypair.secret_key);
        let crypto_provider = OpensslCryptoProvider::new();
        let basic_credential = BasicCredential::new(id);
        let signing_identity = SigningIdentity::new(basic_credential.into_credential(), public_key);
        LiteClient {
            inner: Client::builder()
                .crypto_provider(crypto_provider)
                .identity_provider(BasicIdentityProvider::new())
                .signing_identity(signing_identity, secret_key, cipher_suite)
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
    pub fn generate_key_package_message(&self) -> Result<LiteMessage, MlsError> {
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
    pub fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<LiteGroup, MlsError> {
        let extensions = mls_rs::ExtensionList::new();
        let inner = match group_id {
            Some(group_id) => self.inner.create_group_with_id(group_id, extensions)?,
            None => self.inner.create_group(extensions)?,
        };
        Ok(LiteGroup { inner })
    }

    /// Join an existing group.
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub fn join_group(
        &self,
        welcome_message: mls_rs::MlsMessage,
    ) -> Result<(LiteGroup, LiteNewMemberInfo), MlsError> {
        let (group, new_member_info) = self.inner.join_group(None, welcome_message)?;
        Ok((
            LiteGroup { inner: group },
            LiteNewMemberInfo {
                inner: new_member_info,
            },
        ))
    }
}

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
pub struct LiteGroup {
    inner: mls_rs::Group<LiteConfig>,
}

impl LiteGroup {
    /// Extract the basic credential identifier from a key package.
    fn key_package_into_identifier(message: mls_rs::MlsMessage) -> Result<Vec<u8>, MlsError> {
        let key_package = message
            .into_key_package()
            .ok_or(MlsError::UnexpectedMessageType)?;
        let signing_identity = key_package.signing_identity();
        let Credential::Basic(credential) = &signing_identity.credential else {
            return Err(MlsError::RequiredCredentialNotFound(
                BasicCredential::credential_type(),
            ));
        };

        Ok(credential.identifier.clone())
    }

    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// See [`mls_rs::Group::commit`] for details.
    pub fn commit(&mut self) -> Result<mls_rs::group::CommitOutput, MlsError> {
        self.inner.commit(Vec::new())
    }

    /// Commit the addition of a member.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::group::CommitBuilder::add_member`] for details.
    pub fn add_member(
        &mut self,
        member: LiteMessage,
    ) -> Result<mls_rs::group::CommitOutput, MlsError> {
        self.inner
            .commit_builder()
            .add_member(member.inner)?
            .build()
    }

    /// Propose to add a member to this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::Group::propose_add`] for details.
    pub fn propose_add_member(&mut self, member: LiteMessage) -> Result<LiteMessage, MlsError> {
        let inner = self.inner.propose_add(member.inner, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Propose and commit the removal of a member.
    ///
    /// The member is representated by the key package in `member`.
    ///
    /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    pub fn remove_member(
        &mut self,
        member: LiteMessage,
    ) -> Result<mls_rs::group::CommitOutput, MlsError> {
        let identifier = LiteGroup::key_package_into_identifier(member.inner)?;
        let member = self.inner.member_with_identity(&identifier)?;
        self.inner
            .commit_builder()
            .remove_member(member.index)?
            .build()
    }

    /// Propose to remove a member from this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::group::Group::propose_remove`] for details.
    pub fn propose_remove_member(&mut self, member: LiteMessage) -> Result<LiteMessage, MlsError> {
        let identifier = LiteGroup::key_package_into_identifier(member.inner)?;
        let member = self.inner.member_with_identity(&identifier)?;
        let inner = self.inner.propose_remove(member.index, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Apply a pending commit.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn apply_pending_commit(&mut self) -> Result<(), MlsError> {
        self.inner.apply_pending_commit()?;
        Ok(())
    }

    /// Current group roster.
    ///
    /// This gives you access to the members of the group.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn roster(&self) -> mls_rs::group::Roster<'_> {
        self.inner.roster()
    }
}