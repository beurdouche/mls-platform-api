use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, Mutex},
};

use mls_rs::{
    client_builder::MlsConfig,
    crypto::SignatureSecretKey,
    identity::SigningIdentity,
    mls_rs_codec::{MlsDecode, MlsEncode},
    storage_provider::{EpochRecord, GroupState, KeyPackageData},
    CipherSuite, Client, GroupStateStorage, KeyPackageStorage, MlsMessage,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{GroupConfig, MlsError};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct GroupData {
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
    pub groups: Arc<Mutex<HashMap<Vec<u8>, GroupData>>>,
    /// signing identity => key data
    pub sigkeys: HashMap<Vec<u8>, SignatureData>,
    // pub key_packages: Arc<Mutex<HashMap<Vec<u8>, MlsMessage>>>,
    pub key_packages: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData2>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct SignatureData {
    pub cs: u16,
    #[serde(with = "hex::serde")]
    pub secret_key: Vec<u8>,
}

impl PlatformState {
    pub fn new() -> Result<Self, mls_rs::mls_rs_codec::Error> {
        Ok(Self {
            groups: Default::default(),
            sigkeys: Default::default(),
            key_packages: Default::default(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn client(
        &self,
        myself: SigningIdentity,
        group_config: Option<GroupConfig>,
    ) -> Result<Client<impl MlsConfig>, MlsError> {
        let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();

        let myself_sigkey = self
            .sigkeys
            .get(&myself.mls_encode_to_vec().unwrap())
            .unwrap();

        let mut builder = mls_rs::Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(mls_rs::identity::basic::BasicIdentityProvider)
            .group_state_storage(self.clone())
            .signing_identity(
                myself,
                myself_sigkey.secret_key.clone().into(),
                myself_sigkey.cs.into(),
            );

        if let Some(config) = group_config {
            builder = builder
                .key_package_extensions(config.options)
                .protocol_version(config.version);
        }

        Ok(builder.build())
    }
}

impl GroupStateStorage for PlatformState {
    type Error = mls_rs::mls_rs_codec::Error;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .groups
            .lock()
            .unwrap()
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

impl KeyPackageStorage for PlatformState {
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
