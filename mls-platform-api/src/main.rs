use std::ops::Index;

use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use mls_rs::identity::basic::BasicCredential;
use mls_rs::mls_rs_codec::MlsEncode;

fn main() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_alice = mls_platform_api::state_access("alice.db".into(), [0u8; 32])?;
    let mut state_bob = mls_platform_api::state_access("bob.db".into(), [0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;

    // Create signature keypairs and store them in the state
    let alice_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        group_config.ciphersuite,
    )?;

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&mut state_bob, group_config.ciphersuite)?;

    dbg!("Alice identifier", hex::encode(&alice_id));
    dbg!("Bob identifier", hex::encode(&bob_id));

    // Create Key Package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &mut state_bob,
        bob_id.clone(),
        bob_cred,
        None,
        None,
        None,
    )?;

    dbg!(format!("{bob_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_alice,
        &alice_id,
        alice_cred,
        None,
        None,
        None,
        None,
    )?;

    dbg!("Group created", hex::encode(&gid));

    // Add bob
    let commit_outputs =
        mls_platform_api::mls_group_add(&mut state_alice, &gid, &alice_id, vec![bob_kp])?;
    let welcome = commit_outputs.index(0).welcome.clone().remove(0);
    mls_platform_api::mls_receive(&state_alice, &gid, &alice_id, MlsMessageOrAck::Ack)?;

    // Bob joins
    mls_platform_api::mls_group_confirm_join(&state_bob, &bob_id, welcome.clone(), None)?;

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_send(&state_bob, &gid, &bob_id, b"hello")?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_alice,
        &gid,
        &alice_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
    )?;

    dbg!(format!("{message:?}"));

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_alice, &gid, &alice_id)?;
    dbg!(format!("{members:?}"));

    // Generate an exporter for the Group
    let exporter = mls_platform_api::mls_export(
        &state_alice,
        &gid,
        &alice_id,
        "exporter label".as_bytes(),
        "exporter context".as_bytes(),
        32,
    )?;
    dbg!(format!("{exporter:?}"));

    Ok(())
}
