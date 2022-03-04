use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, KeyPackageRepository, Keychain, Signer};
use crate::extension::ExtensionList;

pub use crate::group::framing::{ContentType, MLSMessage};

use crate::group::framing::Content;
use crate::group::{
    proposal::Proposal, CommitGeneration, Group, OutboundPlaintext, StateUpdate, VerifiedPlaintext,
    Welcome,
};
use crate::key_package::{
    KeyPackage, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRef,
};
use crate::psk::ExternalPskId;
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use crate::ProtocolVersion;
use ferriscrypt::hpke::kem::HpkePublicKey;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use crate::group::{GroupError, ProcessedMessage};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    ProtocolError(#[from] GroupError),
    #[error(transparent)]
    Serialization(#[from] tls_codec::Error),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error("signer not found")]
    SignerNotFound,
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ProposalRejected(Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct PendingCommit {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    packet_data: Vec<u8>,
    commit: CommitGeneration,
}

#[derive(Clone, Debug)]
pub struct CommitResult {
    pub commit_packet: Vec<u8>,
    pub welcome_packet: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Session<C: ClientConfig> {
    protocol: Group,
    pending_commit: Option<PendingCommit>,
    config: C,
}

#[derive(Clone, Debug)]
pub struct GroupStats {
    pub total_leaves: u32,
    pub current_index: u32,
    pub direct_path: Vec<HpkePublicKey>,
    pub epoch: u64,
}

impl<C: ClientConfig + Clone> Session<C> {
    pub(crate) fn create<S: Signer>(
        group_id: Vec<u8>,
        key_package_generator: KeyPackageGenerator<S>,
        group_context_extensions: ExtensionList,
        config: C,
    ) -> Result<Self, SessionError> {
        let group = Group::new(group_id, key_package_generator, group_context_extensions)?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
            config,
        })
    }

    pub(crate) fn join(
        key_package: Option<&KeyPackageRef>,
        ratchet_tree_data: Option<&[u8]>,
        welcome_message_data: &[u8],
        config: C,
    ) -> Result<Self, SessionError> {
        let welcome_message = Welcome::tls_deserialize(&mut &*welcome_message_data)?;

        let key_package_generation = match key_package {
            Some(r) => config.key_package_repo().get(r),
            None => welcome_message
                .secrets
                .iter()
                .find_map(|secrets| {
                    config
                        .key_package_repo()
                        .get(&secrets.new_member)
                        .transpose()
                })
                .transpose(),
        }
        .map_err(|e| SessionError::KeyPackageRepoError(e.into()))?
        .ok_or(SessionError::KeyPackageNotFound)?;

        let ratchet_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(&welcome_message, rt))
            .transpose()?;

        let group = Group::from_welcome_message(
            welcome_message,
            ratchet_tree,
            key_package_generation,
            &config.secret_store(),
            |version, cs| {
                config.supported_protocol_versions().contains(&version)
                    && config.supported_cipher_suites().contains(&cs)
            },
        )?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
            config,
        })
    }

    pub fn join_subgroup(
        &self,
        welcome: Welcome,
        ratchet_tree_data: Option<&[u8]>,
    ) -> Result<Self, SessionError> {
        let public_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(&welcome, rt))
            .transpose()?;
        Ok(Session {
            protocol: self.protocol.join_subgroup(
                welcome,
                public_tree,
                &self.config.secret_store(),
                |version, cs| {
                    self.config.supported_protocol_versions().contains(&version)
                        && self.config.supported_cipher_suites().contains(&cs)
                },
            )?,
            pending_commit: None,
            config: self.config.clone(),
        })
    }

    fn import_ratchet_tree(
        welcome_message: &Welcome,
        tree_data: &[u8],
    ) -> Result<TreeKemPublic, SessionError> {
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        TreeKemPublic::import_node_data(welcome_message.cipher_suite, nodes).map_err(Into::into)
    }

    pub fn participant_count(&self) -> u32 {
        self.protocol
            .current_epoch_tree()
            .map_or(0, |t| t.occupied_leaf_count())
    }

    pub fn roster(&self) -> Vec<&KeyPackage> {
        self.protocol
            .current_epoch_tree()
            .map_or(vec![], |t| t.get_key_packages())
    }

    pub fn current_key_package(&self) -> Result<&KeyPackage, GroupError> {
        self.protocol.current_user_key_package().map_err(Into::into)
    }

    pub fn current_user_ref(&self) -> &KeyPackageRef {
        self.protocol.current_user_ref()
    }

    #[inline]
    pub fn add_proposal(&mut self, key_package_data: &[u8]) -> Result<Proposal, SessionError> {
        let key_package = Deserialize::tls_deserialize(&mut &*key_package_data)?;
        self.protocol.add_proposal(key_package).map_err(Into::into)
    }

    #[inline(always)]
    pub fn update_proposal(&mut self) -> Result<Proposal, SessionError> {
        let key_package = self.protocol.current_user_key_package()?;

        let generator = KeyPackageGenerator {
            protocol_version: self.protocol.protocol_version,
            cipher_suite: self.protocol.cipher_suite,
            signing_key: &self
                .config
                .keychain()
                .signer(&key_package.credential)
                .ok_or(SessionError::SignerNotFound)?,
            credential: &key_package.credential.clone(),
            extensions: &key_package.extensions.clone(),
        };

        self.protocol
            .update_proposal(&generator)
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn remove_proposal(
        &mut self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Proposal, SessionError> {
        self.protocol
            .remove_proposal(key_package_ref)
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, SessionError> {
        Ok(self.protocol.psk_proposal(psk)?)
    }

    #[inline(always)]
    pub fn reinit_proposal(
        &mut self,
        group_id: Vec<u8>,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Proposal, SessionError> {
        Ok(self
            .protocol
            .reinit_proposal(group_id, protocol_version, cipher_suite, extensions)?)
    }

    #[inline(always)]
    pub fn propose_add(&mut self, key_package_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let key_package = KeyPackage::tls_deserialize(&mut &*key_package_data)?;
        self.send_proposal(self.protocol.add_proposal(key_package)?)
    }

    #[inline(always)]
    pub fn propose_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let proposal = self.update_proposal()?;
        self.send_proposal(proposal)
    }

    #[inline(always)]
    pub fn propose_remove(
        &mut self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Vec<u8>, SessionError> {
        let remove = self.remove_proposal(key_package_ref)?;
        self.send_proposal(remove)
    }

    #[inline(always)]
    pub fn group_context_extension_proposal(&self, extension_list: ExtensionList) -> Proposal {
        self.protocol
            .group_context_extensions_proposal(extension_list)
    }

    #[inline(always)]
    pub fn propose_group_context_extension_update(
        &mut self,
        extension_list: ExtensionList,
    ) -> Result<Vec<u8>, SessionError> {
        let extension_update = self.group_context_extension_proposal(extension_list);
        self.send_proposal(extension_update)
    }

    #[inline(always)]
    pub fn propose_psk(&mut self, psk: ExternalPskId) -> Result<Vec<u8>, SessionError> {
        let proposal = self.protocol.psk_proposal(psk)?;
        self.send_proposal(proposal)
    }

    #[inline(always)]
    fn serialize_control(&mut self, plaintext: OutboundPlaintext) -> Result<Vec<u8>, SessionError> {
        Ok(plaintext.into_message().tls_serialize_detached()?)
    }

    fn send_proposal(&mut self, proposal: Proposal) -> Result<Vec<u8>, SessionError> {
        let key_package = self.protocol.current_user_key_package()?;

        let signer = self
            .config
            .keychain()
            .signer(&key_package.credential)
            .ok_or(SessionError::SignerNotFound)?;

        let packet = self.protocol.create_proposal(
            proposal,
            &signer,
            self.config.preferences().encrypt_controls,
        )?;

        self.serialize_control(packet)
    }

    // TODO: You should be able to skip sending a path update if this is an add only commit
    pub fn commit(&mut self, proposals: Vec<Proposal>) -> Result<CommitResult, SessionError> {
        if self.pending_commit.is_some() {
            return Err(SessionError::ExistingPendingCommit);
        }

        let key_package = self.protocol.current_user_key_package()?;

        let signer = self
            .config
            .keychain()
            .signer(&key_package.credential)
            .ok_or(SessionError::SignerNotFound)?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version: self.protocol.protocol_version,
            cipher_suite: self.protocol.cipher_suite,
            credential: &key_package.credential.clone(),
            extensions: &key_package.extensions.clone(),
            signing_key: &signer,
        };

        let preferences = self.config.preferences();

        let (commit_data, welcome) = self.protocol.commit_proposals(
            proposals,
            &key_package_generator,
            true,
            preferences.encrypt_controls,
            preferences.ratchet_tree_extension,
            &self.config.secret_store(),
        )?;

        let serialized_commit = self.serialize_control(commit_data.plaintext.clone())?;

        self.pending_commit = Some(PendingCommit {
            packet_data: serialized_commit.clone(),
            commit: commit_data,
        });

        Ok(CommitResult {
            commit_packet: serialized_commit,
            welcome_packet: welcome.map(|w| w.tls_serialize_detached()).transpose()?,
        })
    }

    pub fn process_incoming_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<ProcessedMessage, SessionError> {
        self.process_incoming_message(MLSMessage::tls_deserialize(&mut &*data)?)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage, SessionError> {
        match message {
            MLSMessage::Plain(message) => {
                let message = self.protocol.verify_incoming_plaintext(message, |id| {
                    self.config.external_signing_key(id)
                })?;
                self.process_incoming_plaintext(message)
            }
            MLSMessage::Cipher(message) => {
                let message = self.protocol.verify_incoming_ciphertext(message, |id| {
                    self.config.external_signing_key(id)
                })?;
                self.process_incoming_plaintext(message)
            }
            MLSMessage::Welcome(message) => Ok(ProcessedMessage::Welcome(message)),
            MLSMessage::GroupInfo(message) => Ok(ProcessedMessage::GroupInfo(message)),
            MLSMessage::KeyPackage(message) => Ok(ProcessedMessage::KeyPackage(message)),
        }
    }

    fn process_incoming_plaintext(
        &mut self,
        message: VerifiedPlaintext,
    ) -> Result<ProcessedMessage, SessionError> {
        match &message.content.content {
            Content::Proposal(p) => self
                .config
                .filter_proposal(p)
                .map_err(|e| SessionError::ProposalRejected(e.into())),
            Content::Application(_) | Content::Commit(_) => Ok(()),
        }?;
        let res = self
            .protocol
            .process_incoming_message(message, &self.config.secret_store())?;
        // This commit beat our current pending commit to the server, our commit is no longer
        // relevant
        if let ProcessedMessage::Commit(_) = res {
            self.pending_commit = None;
        }
        Ok(res)
    }

    pub fn apply_pending_commit(&mut self) -> Result<StateUpdate, SessionError> {
        // take() will give us the value and set it to None in the session
        let pending = self
            .pending_commit
            .take()
            .ok_or(SessionError::PendingCommitNotFound)?;
        self.protocol
            .process_pending_commit(pending.commit, &self.config.secret_store())
            .map_err(Into::into)
    }

    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None
    }

    fn signer(&self) -> Result<<<C as ClientConfig>::Keychain as Keychain>::Signer, SessionError> {
        let key_package = self.protocol.current_user_key_package()?;

        self.config
            .keychain()
            .signer(&key_package.credential)
            .ok_or(SessionError::SignerNotFound)
    }

    pub fn encrypt_application_data(&mut self, data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let ciphertext = self
            .protocol
            .encrypt_application_message(data, &self.signer()?)?;

        Ok(MLSMessage::Cipher(ciphertext).tls_serialize_detached()?)
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.protocol
            .current_epoch_tree()?
            .export_node_data()
            .tls_serialize_detached()
            .map_err(Into::into)
    }

    pub fn has_equal_state(&self, other: &Self) -> bool {
        self.protocol == other.protocol
    }

    pub fn group_stats(&self) -> Result<GroupStats, SessionError> {
        let direct_path = self
            .protocol
            .current_direct_path()?
            .iter()
            .map(|p| p.as_ref().unwrap_or(&vec![].into()).clone())
            .collect();

        Ok(GroupStats {
            total_leaves: self.participant_count(),
            current_index: self.protocol.current_user_index(),
            direct_path,
            epoch: self.protocol.current_epoch(),
        })
    }

    pub fn branch<F>(
        &self,
        sub_group_id: Vec<u8>,
        resumption_psk_epoch: Option<u64>,
        key_pkg_filter: F,
    ) -> Result<(Self, Option<Welcome>), SessionError>
    where
        F: FnMut(&KeyPackageRef) -> bool,
    {
        let (new_group, welcome) = self.protocol.branch(
            sub_group_id,
            resumption_psk_epoch,
            &self.config.secret_store(),
            &self.signer()?,
            key_pkg_filter,
        )?;

        let new_session = Session {
            protocol: new_group,
            pending_commit: None,
            config: self.config.clone(),
        };

        Ok((new_session, welcome))
    }
}
