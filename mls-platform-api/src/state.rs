use std::{
    collections::{hash_map::Entry, HashMap},
    convert::identity,
    path::Path,
    sync::{Arc, Mutex},
};

use mls_rs::{
    client_builder::MlsConfig,
    crypto::SignatureSecretKey,
    error::IntoAnyError,
    group::Capabilities,
    identity::SigningIdentity,
    mls_rs_codec::{MlsDecode, MlsEncode},
    storage_provider::{EpochRecord, GroupState, KeyPackageData},
    CipherSuite, Client, ExtensionList, GroupStateStorage, KeyPackageStorage, ProtocolVersion,
};

use mls_rs::CipherSuiteProvider;
use mls_rs::CryptoProvider;
use mls_rs_crypto_rustcrypto;

use mls_rs_provider_sqlite::{
    connection_strategy::{
        CipheredConnectionStrategy, ConnectionStrategy, FileConnectionStrategy, SqlCipherConfig,
        SqlCipherKey,
    },
    SqLiteDataStorageEngine,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{GroupConfig, Identity, PlatformError};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupData {
    state_data: Vec<u8>,
    epoch_data: HashMap<u64, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct KeyPackageData2 {
    pub key_package_data: KeyPackageData,
}

//
// Hack as I can't figure out how to implement Serialize/Deserialize for KeyPackageData
// TODO: Discuss with Marta
//
impl Serialize for KeyPackageData2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize `KeyPackageData` using `MlsEncode` and then serialize the resulting byte array
        let encoded = self
            .key_package_data
            .mls_encode_to_vec()
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&encoded)
    }
}

impl<'de> Deserialize<'de> for KeyPackageData2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize byte array and then use `MlsDecode` to get `KeyPackageData`
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let key_package_data =
            KeyPackageData::mls_decode(&mut bytes.as_slice()).map_err(serde::de::Error::custom)?;
        Ok(KeyPackageData2 { key_package_data })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PlatformState {
    pub db_path: String,
    pub db_key: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct TemporaryState {
    pub groups: Arc<Mutex<HashMap<Vec<u8>, GroupData>>>,
    /// signing identity => key data
    pub sigkeys: HashMap<Vec<u8>, SignatureData>,
    pub key_packages: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData2>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SignatureData {
    #[serde(with = "hex::serde")]
    pub identifier: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    pub cs: u16,
    #[serde(with = "hex::serde")]
    pub secret_key: Vec<u8>,
}

impl PlatformState {
    pub fn new(db_path: String, db_key: [u8; 32]) -> Result<Self, PlatformError> {
        let state = Self { db_path, db_key };

        // This will create an empty database if it doesn't exist.
        state
            .get_sqlite_engine()?
            .application_data_storage()
            .map_err(|e| (PlatformError::StorageError(e.into_any_error())))?;

        Ok(state)
    }

    pub fn get_signing_identities(&self) -> Result<Vec<Identity>, PlatformError> {
        todo!();
    }

    pub fn client(
        &self,
        myself_identifier: &[u8],
        version: ProtocolVersion,
        key_package_extensions: Option<ExtensionList>,
        leaf_node_extensions: Option<ExtensionList>,
        group_context_extensions: Option<ExtensionList>,
        capabilities: Option<Capabilities>,
    ) -> Result<Client<impl MlsConfig>, PlatformError> {
        let crypto_provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();
        let myself_sig_data = self
            .get_sig_data(myself_identifier)?
            .ok_or(PlatformError::UnavailableSecret)?;
        let engine = self.get_sqlite_engine()?;

        let mut builder = mls_rs::client_builder::ClientBuilder::new_sqlite(engine)
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))?
            .crypto_provider(crypto_provider)
            .identity_provider(mls_rs::identity::basic::BasicIdentityProvider)
            .signer(myself_sig_data.secret_key.into());

        if let Some(key_package_extensions) = key_package_extensions {
            builder = builder
                .key_package_extensions(key_package_extensions)
                .protocol_version(version);
        };
        Ok(builder.build())
    }

    pub fn client_default(
        &self,
        myself_identifier: &[u8],
    ) -> Result<Client<impl MlsConfig>, PlatformError> {
        self.client(
            myself_identifier,
            ProtocolVersion::MLS_10,
            None,
            None,
            None,
            None,
        )
    }

    pub fn insert_sigkey(
        &mut self,
        myself_sigkey: &SignatureSecretKey,
        cs: CipherSuite,
    ) -> Result<(), PlatformError> {
        let crypto_provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();

        let cipher_suite_provider = crypto_provider
            .cipher_suite_provider(cs)
            .ok_or(PlatformError::UnsupportedCiphersuite)?;

        let signature_secret_key = myself_sigkey.to_vec().into();
        let signature_public_key = cipher_suite_provider
            .signature_key_derive_public(&signature_secret_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

        let identity = cipher_suite_provider
            .hash(&signature_public_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

        let signature_data = SignatureData {
            identifier: identity,
            public_key: signature_public_key.to_vec(),
            cs: *cs,
            secret_key: myself_sigkey.to_vec(),
        };

        let key = &signature_data.identifier;

        let engine = self.get_sqlite_engine()?;
        let storage = engine
            .application_data_storage()
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))?;
        let data = bincode::serialize(&signature_data)?;

        storage
            .insert(hex::encode(key), data)
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))?;
        Ok(())
    }

    pub fn get_sig_data(
        &self,
        myself_identifier: &[u8],
    ) -> Result<Option<SignatureData>, PlatformError> {
        // TODO: Not clear if the option is needed here, the underlying function needs it.
        let key = myself_identifier;
        let engine = self.get_sqlite_engine()?;
        let storage = engine
            .application_data_storage()
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))?;

        storage
            .get(&hex::encode(key))
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))?
            .map_or_else(
                || Ok(None),
                |data| bincode::deserialize(&data).map(Some).map_err(Into::into),
            )
    }

    fn get_sqlite_engine(
        &self,
    ) -> Result<SqLiteDataStorageEngine<impl ConnectionStrategy>, PlatformError> {
        let path = Path::new(&self.db_path);
        let file_conn = FileConnectionStrategy::new(path);

        let cipher_config = SqlCipherConfig::new(SqlCipherKey::RawKey(self.db_key));
        let cipher_conn = CipheredConnectionStrategy::new(file_conn, cipher_config);

        SqLiteDataStorageEngine::new(cipher_conn)
            .map_err(|e| PlatformError::StorageError(e.into_any_error()))
    }

    pub fn delete(db_path: String) -> Result<(), PlatformError> {
        let path = Path::new(&db_path);

        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }
}

impl TemporaryState {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PlatformError> {
        bincode::serialize(self).map_err(Into::into)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PlatformError> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    pub fn client(
        &self,
        myself: SigningIdentity,
        group_config: Option<GroupConfig>,
    ) -> Result<Client<impl MlsConfig>, PlatformError> {
        let crypto_provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();
        let myself_sigkey = self.get_sigkey(&myself)?;

        let mut builder = mls_rs::client_builder::ClientBuilder::new()
            .key_package_repo(self.clone())
            .group_state_storage(self.clone())
            .crypto_provider(crypto_provider)
            .identity_provider(mls_rs::identity::basic::BasicIdentityProvider)
            .signing_identity(
                myself,
                myself_sigkey.secret_key.into(),
                myself_sigkey.cs.into(),
            );

        if let Some(config) = group_config {
            builder = builder
                .key_package_extensions(config.options)
                .protocol_version(config.version);
        }

        Ok(builder.build())
    }

    pub fn insert_sigkey(
        &mut self,
        myself_identifier: &[u8],
        myself: &SigningIdentity,
        myself_sigkey: &SignatureSecretKey,
        cs: CipherSuite,
    ) -> Result<(), PlatformError> {
        let crypto_provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::default();

        let cipher_suite_provider = crypto_provider
            .cipher_suite_provider(cs)
            .ok_or(PlatformError::UnsupportedCiphersuite)?;

        let signature_secret_key = myself_sigkey.to_vec().into();
        let signature_public_key = cipher_suite_provider
            .signature_key_derive_public(&signature_secret_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

        let identity = cipher_suite_provider
            .hash(&signature_public_key)
            .map_err(|e| PlatformError::CryptoError(e.into_any_error()))?;

        let signature_data = SignatureData {
            identifier: identity,
            public_key: signature_public_key.to_vec(),
            cs: *cs,
            secret_key: myself_sigkey.to_vec(),
        };

        let key = myself_identifier.to_vec();

        self.sigkeys.insert(key, signature_data);
        // TODO: We could return the value to indicate if the key
        // existed (see the definition of insert).
        Ok(())
    }

    pub fn get_sigkey(&self, myself: &SigningIdentity) -> Result<SignatureData, PlatformError> {
        let key = myself.mls_encode_to_vec()?;

        self.sigkeys
            .get(&key)
            .cloned()
            .ok_or(PlatformError::UnavailableSecret)
    }
}

impl GroupStateStorage for TemporaryState {
    type Error = mls_rs::mls_rs_codec::Error;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let group_locked = self.groups.lock().unwrap();

        Ok(group_locked
            .get(group_id)
            .and_then(|group_data| group_data.epoch_data.keys().max().copied()))
    }

    fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: GroupState + MlsDecode,
    {
        self.groups
            .lock()
            .unwrap()
            .get(group_id)
            .map(|v| T::mls_decode(&mut v.state_data.as_slice()))
            .transpose()
            .map_err(Into::into)
    }

    fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: EpochRecord + MlsEncode + MlsDecode,
    {
        self.groups
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|group_data| group_data.epoch_data.get(&epoch_id))
            .map(|v| T::mls_decode(&mut &v[..]))
            .transpose()
            .map_err(Into::into)
    }

    fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + MlsEncode + MlsDecode + Send + Sync,
        ET: EpochRecord + MlsEncode + MlsDecode + Send + Sync,
    {
        let state_data = state.mls_encode_to_vec()?;
        let mut states = self.groups.lock().unwrap();

        let group_data = match states.entry(state.id()) {
            Entry::Occupied(entry) => {
                let data = entry.into_mut();
                data.state_data = state_data;
                data
            }
            Entry::Vacant(entry) => entry.insert(GroupData {
                state_data,
                epoch_data: Default::default(),
            }),
        };

        epoch_inserts.into_iter().try_for_each(|e| {
            group_data.epoch_data.insert(e.id(), e.mls_encode_to_vec()?);
            Ok::<_, Self::Error>(())
        })?;

        epoch_updates.into_iter().try_for_each(|e| {
            if let Some(data) = group_data.epoch_data.get_mut(&e.id()) {
                *data = e.mls_encode_to_vec()?;
            };

            Ok::<_, Self::Error>(())
        })?;

        Ok(())
    }
}

impl KeyPackageStorage for TemporaryState {
    type Error = mls_rs::mls_rs_codec::Error;

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        // Convert KeyPackageData to KeyPackageData2
        let pkg2 = KeyPackageData2 {
            key_package_data: pkg,
        };

        let mut states = self.key_packages.lock().unwrap();
        states.insert(id, pkg2);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let states = self.key_packages.lock().unwrap();
        // Retrieve KeyPackageData2 and convert it to KeyPackageData
        match states.get(id) {
            Some(pkg2) => Ok(Some(pkg2.key_package_data.clone())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let mut states = self.key_packages.lock().unwrap();
        states.remove(id);
        Ok(())
    }
}
