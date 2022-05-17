use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client::Client,
    credential::{Credential, CredentialError},
    extension::{CapabilitiesExt, ExtensionList, ExtensionType, LifetimeExt},
    group::{proposal::Proposal, CommitOptions, ControlEncryptionMode, GroupConfig},
    key_package::{InMemoryKeyPackageRepository, KeyPackageRepository},
    keychain::{InMemoryKeychain, Keychain, SigningIdentity},
    psk::{ExternalPskId, Psk},
    time::MlsTime,
    EpochRepository, InMemoryEpochRepository, ProtocolVersion,
};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};
use thiserror::Error;

pub use crate::group::padding::PaddingMode;

pub const ONE_YEAR_IN_SECONDS: u64 = 365 * 24 * 60 * 60;

pub trait PskStore {
    type Error: std::error::Error + Send + Sync + 'static;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error>;
}

pub trait CredentialValidator {
    type Error: std::error::Error + Send + Sync + 'static;
    fn validate(&self, credential: &Credential) -> Result<(), Self::Error>;
    fn is_equal_identity(&self, left: &Credential, right: &Credential) -> bool;
}

impl<T: CredentialValidator> CredentialValidator for &T {
    type Error = T::Error;

    fn validate(&self, credential: &Credential) -> Result<(), Self::Error> {
        (*self).validate(credential)
    }

    fn is_equal_identity(&self, left: &Credential, right: &Credential) -> bool {
        (*self).is_equal_identity(left, right)
    }
}

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;
    type ProposalFilterError: std::error::Error + Send + Sync + 'static;
    type Keychain: Keychain;
    type PskStore: PskStore;
    type EpochRepository: EpochRepository;
    type CredentialValidator: CredentialValidator;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn preferences(&self) -> Preferences;
    fn external_key_id(&self) -> Option<Vec<u8>>;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), Self::ProposalFilterError>;
    fn keychain(&self) -> Self::Keychain;
    fn secret_store(&self) -> Self::PskStore;
    fn epoch_repo(&self, group_id: &[u8]) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn key_package_extensions(&self) -> ExtensionList;
    fn leaf_node_extensions(&self) -> ExtensionList;
    fn lifetime(&self) -> LifetimeExt;

    fn capabilities(&self) -> CapabilitiesExt {
        CapabilitiesExt {
            protocol_versions: self.supported_protocol_versions(),
            cipher_suites: self
                .supported_cipher_suites()
                .into_iter()
                .map(MaybeCipherSuite::from)
                .collect(),
            extensions: self.supported_extensions(),
            proposals: vec![], // TODO: Support registering custom proposals here
        }
    }

    fn commit_options(&self) -> CommitOptions {
        let preferences = self.preferences();

        CommitOptions {
            prefer_path_update: true,
            extension_update: Some(self.leaf_node_extensions()),
            capabilities_update: Some(self.capabilities()),
            encryption_mode: preferences.encryption_mode(),
            ratchet_tree_extension: preferences.ratchet_tree_extension,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryPskStore {
    inner: Arc<Mutex<HashMap<ExternalPskId, Psk>>>,
}

impl InMemoryPskStore {
    pub fn insert(&mut self, id: ExternalPskId, psk: Psk) -> Option<Psk> {
        self.inner.lock().unwrap().insert(id, psk)
    }
}

impl PskStore for InMemoryPskStore {
    type Error = Infallible;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error> {
        Ok(self.inner.lock().unwrap().get(id).cloned())
    }
}

#[derive(Clone, Debug)]
pub struct Preferences {
    pub encrypt_controls: bool,
    pub ratchet_tree_extension: bool,
    pub padding_mode: PaddingMode,
    pub force_commit_path_update: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            encrypt_controls: Default::default(),
            ratchet_tree_extension: Default::default(),
            padding_mode: Default::default(),
            force_commit_path_update: true,
        }
    }
}

impl Preferences {
    #[must_use]
    pub fn with_control_encryption(self, enabled: bool) -> Self {
        Self {
            encrypt_controls: enabled,
            ..self
        }
    }

    #[must_use]
    pub fn with_ratchet_tree_extension(self, enabled: bool) -> Self {
        Self {
            ratchet_tree_extension: enabled,
            ..self
        }
    }

    #[must_use]
    pub fn with_padding_mode(self, padding_mode: PaddingMode) -> Self {
        Self {
            padding_mode,
            ..self
        }
    }

    #[must_use]
    pub fn force_commit_path_update(self, enabled: bool) -> Self {
        Self {
            force_commit_path_update: enabled,
            ..self
        }
    }

    pub(crate) fn encryption_mode(&self) -> ControlEncryptionMode {
        if self.encrypt_controls {
            ControlEncryptionMode::Encrypted(self.padding_mode)
        } else {
            ControlEncryptionMode::Plaintext
        }
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InMemoryClientConfig {
    preferences: Preferences,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    external_key_id: Option<Vec<u8>>,
    supported_extensions: Vec<ExtensionType>,
    key_packages: InMemoryKeyPackageRepository,
    proposal_filter: Option<ProposalFilter>,
    keychain: InMemoryKeychain,
    psk_store: InMemoryPskStore,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    epochs: Arc<Mutex<HashMap<Vec<u8>, InMemoryEpochRepository>>>,
    leaf_node_extensions: ExtensionList,
    key_package_extensions: ExtensionList,
    lifetime_duration: u64,
}

#[derive(Clone)]
struct ProposalFilter(Arc<dyn Fn(&Proposal) -> Result<(), String> + Send + Sync>);

impl Debug for ProposalFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProposalFilter")
    }
}

impl InMemoryClientConfig {
    pub fn new() -> Self {
        Self {
            preferences: Default::default(),
            external_signing_keys: Default::default(),
            external_key_id: Default::default(),
            supported_extensions: Default::default(),
            key_packages: Default::default(),
            proposal_filter: Default::default(),
            keychain: Default::default(),
            psk_store: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
            epochs: Default::default(),
            leaf_node_extensions: Default::default(),
            key_package_extensions: Default::default(),
            lifetime_duration: ONE_YEAR_IN_SECONDS,
        }
    }

    #[must_use]
    pub fn with_preferences(self, preferences: Preferences) -> Self {
        Self {
            preferences,
            ..self
        }
    }

    #[must_use]
    pub fn with_supported_extension(mut self, extension: ExtensionType) -> Self {
        self.supported_extensions.push(extension);
        self
    }

    #[must_use]
    pub fn with_external_signing_key(mut self, id: Vec<u8>, key: PublicKey) -> Self {
        self.external_signing_keys.insert(id, key);
        self
    }

    #[must_use]
    pub fn with_external_key_id(self, id: Vec<u8>) -> Self {
        Self {
            external_key_id: Some(id),
            ..self
        }
    }

    #[must_use]
    pub fn with_proposal_filter<F, E>(self, f: F) -> Self
    where
        F: Fn(&Proposal) -> Result<(), E> + Send + Sync + 'static,
        E: ToString,
    {
        Self {
            proposal_filter: Some(ProposalFilter(Arc::new(move |p| {
                f(p).map_err(|e| e.to_string())
            }))),
            ..self
        }
    }

    #[must_use]
    pub fn with_psk(mut self, psk_id: ExternalPskId, psk: Psk) -> Self {
        self.psk_store.insert(psk_id, psk);
        self
    }

    #[must_use]
    pub fn with_signing_identity(
        mut self,
        identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> Self {
        self.keychain.insert(identity, secret_key);
        self
    }

    #[must_use]
    pub fn with_protocol_version(mut self, version: ProtocolVersion) -> Self {
        self.protocol_versions.push(version);
        self
    }

    #[must_use]
    pub fn clear_protocol_versions(mut self) -> Self {
        self.protocol_versions.clear();
        self
    }

    #[must_use]
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suites.push(cipher_suite);
        self
    }

    #[must_use]
    pub fn clear_cipher_suites(mut self) -> Self {
        self.cipher_suites.clear();
        self
    }

    pub fn with_key_package_extensions(mut self, extensions: ExtensionList) -> Self {
        self.key_package_extensions = extensions;
        self
    }

    pub fn with_leaf_node_extensions(mut self, extensions: ExtensionList) -> Self {
        self.leaf_node_extensions = extensions;
        self
    }

    #[must_use]
    pub fn with_lifetime_duration(mut self, duration: u64) -> Self {
        self.lifetime_duration = duration;
        self
    }

    pub fn build_client(self) -> Client<Self> {
        Client::new(self)
    }
}

impl Default for InMemoryClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PassthroughCredentialValidator;

impl PassthroughCredentialValidator {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialValidator for PassthroughCredentialValidator {
    type Error = CredentialError;
    fn validate(&self, _credential: &Credential) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_equal_identity(&self, _left: &Credential, _right: &Credential) -> bool {
        true
    }
}

impl ClientConfig for InMemoryClientConfig {
    type KeyPackageRepository = InMemoryKeyPackageRepository;
    type ProposalFilterError = SimpleError;
    type Keychain = InMemoryKeychain;
    type PskStore = InMemoryPskStore;
    type EpochRepository = InMemoryEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn preferences(&self) -> Preferences {
        self.preferences.clone()
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }

    fn key_package_repo(&self) -> InMemoryKeyPackageRepository {
        self.key_packages.clone()
    }

    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), SimpleError> {
        self.proposal_filter
            .as_ref()
            .map_or(Ok(()), |ProposalFilter(f)| f(proposal))
            .map_err(SimpleError)
    }

    fn secret_store(&self) -> Self::PskStore {
        self.psk_store.clone()
    }

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.cipher_suites.clone()
    }

    fn keychain(&self) -> Self::Keychain {
        self.keychain.clone()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.supported_extensions.clone()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.protocol_versions.clone()
    }

    fn epoch_repo(&self, group_id: &[u8]) -> Self::EpochRepository {
        self.epochs
            .lock()
            .unwrap()
            .entry(group_id.to_vec())
            .or_default()
            .clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }

    fn key_package_extensions(&self) -> ExtensionList {
        self.key_package_extensions.clone()
    }

    fn leaf_node_extensions(&self) -> ExtensionList {
        self.leaf_node_extensions.clone()
    }

    fn capabilities(&self) -> CapabilitiesExt {
        CapabilitiesExt {
            protocol_versions: self.supported_protocol_versions(),
            cipher_suites: self
                .supported_cipher_suites()
                .into_iter()
                .map(MaybeCipherSuite::from)
                .collect(),
            extensions: self.supported_extensions(),
            proposals: vec![], // TODO: Support registering custom proposals here
        }
    }

    fn lifetime(&self) -> LifetimeExt {
        let now_timestamp = MlsTime::now().seconds_since_epoch().unwrap();
        LifetimeExt {
            not_before: now_timestamp,
            not_after: now_timestamp + self.lifetime_duration,
        }
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SimpleError(String);

#[derive(Clone, Debug)]
pub struct ClientGroupConfig<C: ClientConfig> {
    pub epoch_repo: C::EpochRepository,
    pub credential_validator: C::CredentialValidator,
}

impl<C: ClientConfig> ClientGroupConfig<C> {
    pub fn new(client_config: &C, group_id: &[u8]) -> Self {
        Self {
            epoch_repo: client_config.epoch_repo(group_id),
            credential_validator: client_config.credential_validator(),
        }
    }
}

impl<C> GroupConfig for ClientGroupConfig<C>
where
    C: ClientConfig,
    C::EpochRepository: Clone,
    C::CredentialValidator: Clone,
{
    type EpochRepository = C::EpochRepository;
    type CredentialValidator = C::CredentialValidator;

    fn epoch_repo(&self) -> Self::EpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        self.credential_validator.clone()
    }
}
