#![allow(dead_code, unused_imports)]

use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::identity::basic::BasicIdentityProvider;
use mls_rs::identity::Credential;
use mls_rs::{CipherSuiteProvider, Client, CryptoProvider};
use mls_rs_core::identity::{BasicCredential, SigningIdentity};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use safer_ffi::ffi_export;
use safer_ffi_gen::{ffi_type, safer_ffi_gen};

#[ffi_type(opaque)]
pub struct GroupContextExtensions {}

#[ffi_type(opaque)]
pub struct GroupConfig {
    protocol_version: mls_rs::ProtocolVersion,
    cipher_suite: mls_rs::CipherSuite,
    context_extensions: mls_rs::ExtensionList,
}

#[ffi_type(opaque)]
pub struct SignatureKeypair {
    public_key: mls_rs::crypto::SignaturePublicKey,
    secret_key: mls_rs::crypto::SignatureSecretKey,
}

pub type LiteConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

#[ffi_type(opaque)]
pub struct LiteNewMemberInfo {
    inner: mls_rs::group::NewMemberInfo,
}

#[ffi_type(opaque)]
pub struct LiteMessage {
    inner: mls_rs::MlsMessage,
}

#[safer_ffi_gen]
impl LiteMessage {
    /// Convert a message into a key package.
    ///
    /// See [`mls_rs::Group::apply_pending_commit`] for details.
    pub fn into_key_package(self) -> Option<mls_rs::KeyPackage> {
        self.inner.into_key_package()
    }
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[ffi_type(opaque)]
pub struct LiteClient {
    inner: mls_rs::client::Client<LiteConfig>,
}

#[safer_ffi_gen]
impl LiteClient {
    /// Generate a MLS signature keypair.
    ///
    /// This will use the default mls-lite crypto provider.
    ///
    /// See [`mls_rs::CipherSuiteProvider::signature_key_generate`]
    /// for details.
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
            public_key,
            secret_key,
        })
    }

    /// Create a new client.
    ///
    /// The user is identified by `id`, which will be used to create a
    /// basic credential together with the signature keypair.
    ///
    /// See [`mls_rs::Client::builder`] for details.
    pub fn new(
        id: Vec<u8>,
        signature_keypair: SignatureKeypair,
        cipher_suite: mls_rs::CipherSuite,
    ) -> LiteClient {
        let crypto_provider = OpensslCryptoProvider::new();
        let basic_credential = BasicCredential::new(id);
        let signing_identity = SigningIdentity::new(
            basic_credential.into_credential(),
            signature_keypair.public_key,
        );
        LiteClient {
            inner: Client::builder()
                .crypto_provider(crypto_provider)
                .identity_provider(BasicIdentityProvider::new())
                .signing_identity(signing_identity, signature_keypair.secret_key, cipher_suite)
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
#[ffi_type(opaque)]
pub struct LiteGroup {
    inner: mls_rs::Group<LiteConfig>,
}

#[safer_ffi_gen]
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
    /// See [`mls_rs::Group::add_member`] for details.
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
    /// See [`mls_rs::Group::propose_add_member`] for details.
    pub fn propose_add_member(&mut self, member: LiteMessage) -> Result<LiteMessage, MlsError> {
        let inner = self.inner.propose_add(member.inner, Vec::new())?;
        Ok(LiteMessage { inner })
    }

    /// Propose and commit the removal of a member.
    ///
    /// The member is representated by the key package in `member`.
    ///
    /// See [`mls_rs::Group::remove_member`] for details.
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
    /// See [`mls_rs::Group::propose_remove_member`] for details.
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

/// Generate C headers.
#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("mls-lite.h")?
        .generate()
}

// Run tests with the address sanitizer:
//
// RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu

#[cfg(test)]
mod tests {
    use std::ptr;

    mod ffi {
        // Regenerate bindings with
        //
        // % cargo run --features headers --bin generate-headers
        // % bindgen --with-derive-default mls-lite.h -o mls-lite.rs
        #![allow(non_upper_case_globals)]
        #![allow(non_camel_case_types)]
        #![allow(non_snake_case)]
        include!("../../mls-lite.rs");
    }

    fn to_vec_uint8(b: &[u8]) -> ffi::Vec_uint8_t {
        let rust_vec = b.to_vec();
        let ffi_vec = safer_ffi::vec::Vec::from(rust_vec);
        // SAFETY: safer_ffi::vec::Vec<u8> is defined to have same
        // representation as Vec_uint8.
        unsafe { std::mem::transmute::<_, _>(ffi_vec) }
    }

    #[track_caller]
    fn assert_pointer_is_set<T>(pointer: *mut T) {
        assert!(!pointer.is_null());
    }

    #[track_caller]
    fn assert_success(exit_code: i32) {
        assert_eq!(exit_code, 0);
    }

    fn make_lite_client(id: &[u8]) -> *mut ffi::LiteClient {
        let cipher_suite = mls_rs::CipherSuite::CURVE25519_AES128;
        let mut signature_keypair = ptr::null_mut();
        // SAFETY: valid cipher suite and aligned pointer.
        assert_success(unsafe {
            ffi::lite_client_generate_signature_keypair(
                *cipher_suite,
                &mut signature_keypair as *mut _,
            )
        });
        assert_pointer_is_set(signature_keypair);
        unsafe { ffi::lite_client_new(to_vec_uint8(id), signature_keypair, *cipher_suite) }
    }

    fn make_lite_group(lite_client: *mut ffi::LiteClient, id: &[u8]) -> *mut ffi::LiteGroup {
        let mut lite_group = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_client_create_group(lite_client, to_vec_uint8(id), &mut lite_group as *mut _)
        });
        lite_group
    }

    fn group_roster_len(group: *mut ffi::LiteGroup) -> usize {
        let roster = unsafe { ffi::lite_group_roster(group) };
        let members = unsafe { ffi::roster_members(roster) };
        let len = members.len;
        unsafe { ffi::member_vec_free(members) };
        unsafe { ffi::roster_free(roster) };
        len
    }

    #[test]
    fn test_lite_client_generate_signature_keypair() {
        let cipher_suite = mls_rs::CipherSuite::CURVE25519_AES128;
        let mut signature_keypair = ptr::null_mut();

        assert_success(unsafe {
            ffi::lite_client_generate_signature_keypair(
                *cipher_suite,
                &mut signature_keypair as *mut _,
            )
        });
        assert_pointer_is_set(signature_keypair);

        unsafe { ffi::signature_keypair_free(signature_keypair) };
    }

    #[test]
    fn test_lite_client_new() {
        let lite_client = make_lite_client(b"alice");
        assert_pointer_is_set(lite_client);
        unsafe { ffi::lite_client_free(lite_client) };
    }

    #[test]
    fn test_lite_client_generate_key_package_message() {
        let lite_client = make_lite_client(b"bob");
        let mut message = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_client_generate_key_package_message(lite_client, &mut message as *mut _)
        });
        assert_pointer_is_set(message);

        let key_package = unsafe { ffi::lite_message_into_key_package(message) };
        assert_pointer_is_set(key_package);

        unsafe { ffi::key_package_free(key_package) };
        unsafe { ffi::lite_client_free(lite_client) };
    }

    #[test]
    fn test_lite_client_create_group() {
        let lite_client = make_lite_client(b"carol");

        let lite_group = make_lite_group(lite_client, b"my group");
        assert_pointer_is_set(lite_group);

        unsafe { ffi::lite_group_free(lite_group) };
        unsafe { ffi::lite_client_free(lite_client) };
    }

    #[test]
    fn test_lite_client_join_group() {
        // Alice creates a group.
        let alice_client = make_lite_client(b"alice");
        let alice_group = make_lite_group(alice_client, b"Alice's group");
        assert_eq!(group_roster_len(alice_group), 1); // alice is in the group

        // Bob creates his key package.
        let bob_client = make_lite_client(b"bob");
        let mut bob_key_package = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_client_generate_key_package_message(
                bob_client,
                &mut bob_key_package as *mut _,
            )
        });

        let mut commit_output = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_group_add_member(alice_group, bob_key_package, &mut commit_output as *mut _)
        });
        assert_pointer_is_set(commit_output);

        let welcome_messages = unsafe { ffi::commit_output_welcome_messages(commit_output) };
        assert_eq!(welcome_messages.len, 1);
        // Clone is needed because we need to pass ownership of
        // `welcome_message` to `join_group` below. This is equivalent
        // of calling `Vec::remove` on `welcome_messages`.
        let welcome_message =
            unsafe { ffi::mls_message_clone(ffi::mls_message_slice_get(welcome_messages, 0)) };
        unsafe { ffi::commit_output_free(commit_output) };

        let mut group_new_member_info = ffi::Tuple2_LiteGroup_ptr_LiteNewMemberInfo_ptr::default();
        assert_success(unsafe {
            ffi::lite_client_join_group(
                bob_client,
                welcome_message as *mut ffi::MlsMessage,
                &mut group_new_member_info as *mut _,
            )
        });
        let (bob_group, bob_new_member_info) = (group_new_member_info._0, group_new_member_info._1);

        assert_pointer_is_set(bob_group);
        assert_pointer_is_set(bob_new_member_info);

        assert_eq!(group_roster_len(alice_group), 1); // alice
        assert_eq!(group_roster_len(bob_group), 2); // alice and bob

        assert_success(unsafe { ffi::lite_group_apply_pending_commit(alice_group) });
        assert_eq!(group_roster_len(alice_group), 2); // alice and bob

        unsafe { ffi::lite_group_free(alice_group) };
        unsafe { ffi::lite_client_free(alice_client) };

        unsafe { ffi::lite_client_free(bob_client) };
        unsafe { ffi::lite_group_free(bob_group) };
        unsafe { ffi::lite_new_member_info_free(bob_new_member_info) };
    }

    #[test]
    fn test_lite_group_add_member() {
        let alice_client = make_lite_client(b"alice");
        let alice_group = make_lite_group(alice_client, b"Alice's group");
        assert_eq!(group_roster_len(alice_group), 1); // alice is in the group

        let bob_client = make_lite_client(b"bob");
        let mut bob_key_package = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_client_generate_key_package_message(
                bob_client,
                &mut bob_key_package as *mut _,
            )
        });

        let mut commit_output = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_group_add_member(alice_group, bob_key_package, &mut commit_output as *mut _)
        });
        assert_pointer_is_set(commit_output);

        assert_eq!(group_roster_len(alice_group), 1); // alice
        assert_success(unsafe { ffi::lite_group_apply_pending_commit(alice_group) });
        assert_eq!(group_roster_len(alice_group), 2); // alice and bob

        unsafe { ffi::commit_output_free(commit_output) };

        unsafe { ffi::lite_group_free(alice_group) };
        unsafe { ffi::lite_client_free(alice_client) };

        unsafe { ffi::lite_client_free(bob_client) };
    }

    #[test]
    fn test_lite_group_remove_member() {
        let alice_client = make_lite_client(b"alice");

        let bob_client = make_lite_client(b"bob");
        let mut bob_key_package = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_client_generate_key_package_message(
                bob_client,
                &mut bob_key_package as *mut _,
            )
        });

        let alice_group = make_lite_group(alice_client, b"Alice's group");
        assert_eq!(group_roster_len(alice_group), 1); // alice is in the group

        // Add bob
        let mut commit_output = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_group_add_member(alice_group, bob_key_package, &mut commit_output as *mut _)
        });
        unsafe { ffi::commit_output_free(commit_output) };
        assert_success(unsafe { ffi::lite_group_apply_pending_commit(alice_group) });
        assert_eq!(group_roster_len(alice_group), 2); // alice and bob

        // The first key package for bob has been consumed by the
        // `add_member` call. Generate a new key package.
        assert_success(unsafe {
            ffi::lite_client_generate_key_package_message(
                bob_client,
                &mut bob_key_package as *mut _,
            )
        });

        let mut commit_output = ptr::null_mut();
        assert_success(unsafe {
            ffi::lite_group_remove_member(
                alice_group,
                bob_key_package,
                &mut commit_output as *mut _,
            )
        });
        unsafe { ffi::commit_output_free(commit_output) };

        assert_eq!(group_roster_len(alice_group), 2); // alice and bob
        assert_success(unsafe { ffi::lite_group_apply_pending_commit(alice_group) });
        assert_eq!(group_roster_len(alice_group), 1); // alice

        unsafe { ffi::lite_group_free(alice_group) };
        unsafe { ffi::lite_client_free(alice_client) };

        unsafe { ffi::lite_client_free(bob_client) };
    }
}
