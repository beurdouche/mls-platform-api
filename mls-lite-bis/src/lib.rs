#![allow(dead_code, unused_imports)]

use std::sync::Arc;

// use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
// use mls_rs::error::{IntoAnyError, MlsError};
// use mls_rs::identity::basic::BasicIdentityProvider;
// use mls_rs::identity::Credential;
// use mls_rs::{CipherSuiteProvider, Client, CryptoProvider};
// use mls_rs_core::identity::{BasicCredential, SigningIdentity};
// use mls_rs_crypto_openssl::OpensslCryptoProvider;

// #[cfg(feature = "uniffi")]
// uniffi::setup_scaffolding!();

// #[cfg(feature = "uniffi")]
// uniffi::ffi_converter_forward!(
//     mls_platform_api::CipherSuite,
//     mls_pl::UniFfiTag,
//     crate::UniFfiTag
// );

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
    public_key: Arc<mls_platform_api::SignaturePublicKey>,
    secret_key: Arc<mls_platform_api::SignatureSecretKey>,
}

pub type LiteConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

/// Light-weight wrapper around a [`mls_rs::group::NewMemberInfo`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteNewMemberInfo {
    inner: mls_platform_api::NewMemberInfo,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteKeyPackage {
    inner: mls_platform_api::KeyPackage,
}

/// Light-weight wrapper around a [`mls_rs::MlsMessage`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteMessage {
    inner: mls_platform_api::MlsMessage,
}

impl LiteMessage {
    /// Convert a message into a key package.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn into_key_package(self) -> Option<mls_platform_api::KeyPackage> {
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
    cipher_suite: mls_platform_api::CipherSuite,
) -> Result<mls_platform_api::SignatureKeypair, mls_platform_api::MlsError> {
    let state = mls_platform_api::state(identifier, key);
    mls_platform_api::generate_signature_keypair(&state, name, cipher_suite, None)?;
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct LiteClient {
    state: mls_platform_api::PlatformState,
    identity: mls_platform_api::SigningIdentity,
    client_config: mls_platform_api::ClientConfig,
    group_config: mls_platform_api::GroupConfig,
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
        signing_identity: mls_platform_api::SignatureIdentity,
        client_config: mls_platform_api::ClientConfig,
        group_config: mls_platform_api::GroupConfig,
    ) -> Self {
        let state = mls_platform_api::PlatformState::new();
        LiteClient {
            state,
            identity: signing_identity,
            client_config,
            group_config,
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
    pub fn generate_key_package_message(
        &self,
    ) -> Result<mls_platform_api::MlsMessage, mls_platform_api::MlsError> {
        let state = mls_platform_api::state(identifier, key);
        mls_generate_key_package(self.state, self.identity, self.group_config, None)?;
    }

    /// Create and immediately join a new group.
    ///
    /// If a group ID is not given, the underlying library will create
    /// a unique ID for you.
    ///
    /// See [`mls_rs::Client::create_group`] and
    /// [`mls_rs::Client::create_group_with_id`] for details.
    type GroupId: Vec<u8>;

    pub fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<GroupId, MlsError> {
        let extensions = mls_rs::ExtensionList::new();
        mls_platform_api::create_group(self.state, self.group_config, group_id, self.identity)
    }

    /// Join an existing group.
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub fn join_group(
        &self,
        welcome_message: mls_rs::MlsMessage,
    ) -> Result<(LiteGroup, LiteNewMemberInfo), MlsError> {
        mls_platform_api::join_group(
            self.state,
            self.identity,
            self.group_config,
            welcome_message,
        )
    }
}

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
pub struct LiteGroup {
    state: mls_platform_api::PlatformState,
    // TODO: This needs to contain the list of clients
    // There is no way to select your Signing Indentity within that group here afaik.
    //???
    current_identity: mls_platform_api::SigningIdentity,
}

impl LiteGroup {
    /// Select one of the identities to be used for signing.
    fn select_identity(&self) -> mls_platform_api::SigningIdentity {
        todo!() // List identities and select one for the group state
    }

    /// Extract the basic credential identifier from a key package.
    fn key_package_into_identifier(
        message: mls_platform_api::MlsMessage,
    ) -> Result<Vec<u8>, mls_platform_api::MlsError> {
        mls_platform_api::key_package_into_identifier(message)
    }

    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// See [`mls_rs::Group::commit`] for details.

    /// BB. Not sure if this should be exposed at all.
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
        member: mls_platform_api::MlsMessage,
    ) -> Result<mls_platform_api::MlsMessage, mls_platform_api::MlsError> {
        mls_platform_api::group_add(
            self.state,
            self.gid,
            self.config,
            member,
            self.current_identity,
        )?
    }

    /// Propose to add a member to this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::Group::propose_add`] for details.
    pub fn propose_add_member(
        &mut self,
        member: LiteMessage,
    ) -> Result<mls_platform_api::MlsMessage, mls_platform_api::MlsError> {
        mls_platform_api::group_propose_add(
            self.state,
            self.gid,
            self.config,
            member,
            self.current_identity,
        )?
    }

    /// Propose and commit the removal of a member.
    ///
    /// The member is representated by the key package in `member`.
    ///
    /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    pub fn remove_member(
        &mut self,
        member: SigningIdentity,
    ) -> Result<mls_platform_api::MlsMessage, mls_platform_api::MlsError> {
        mls_platform_api::group_remove(
            self.state,
            self.gid,
            self.config,
            member,
            self.current_identity,
        )?
    }

    /// Propose to remove a member from this group.
    ///
    /// The member is representated by the key package in `member`.
    /// The result is the welcome message to send to this member.
    ///
    /// See [`mls_rs::group::Group::propose_remove`] for details.
    pub fn propose_remove_member(
        &mut self,
        member: SigningIdentity,
    ) -> Result<mls_platform_api::MlsMessage, mls_platform_api::MlsError> {
        mls_platform_api::group_propose_remove(
            self.state,
            self.gid,
            self.config,
            member,
            self.current_identity,
        )?
    }

    /// Apply a pending commit.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn apply_pending_commit(&mut self) -> Result<(), MlsError> {
        todo!();
        Ok(())
    }

    /// Current group roster.
    ///
    /// This gives you access to the members of the group.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn members(&self) -> mls_platform_api::Vec<SignatureIdentity> {
        mls_platform_api::group_members(self.state, self.gid)
    }
}
