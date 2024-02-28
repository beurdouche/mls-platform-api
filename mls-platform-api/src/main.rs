use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use mls_rs::identity::basic::BasicCredential;

fn main() -> Result<(), PlatformError> {
    let group_config = mls_platform_api::GroupConfig::default();

    let mut state_alice = mls_platform_api::state_access("alice".into(), [0u8; 32])?;
    let mut state_bob = mls_platform_api::state_access("bob".into(), [0u8; 32])?;

    //let alice_cred = BasicCredential::new(b"alice");

    // Create signature keypairs
    let alice_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        group_config.ciphersuite,
    )?;

    dbg!(String::from_utf8(alice_id.clone()).unwrap());

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&mut state_bob, group_config.ciphersuite)?;

    // Create key package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(&mut state_bob)?;

    dbg!(format!("{bob_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_alice,
        &alice_id,
        None,
        Some(group_config.clone()),
    )?;

    dbg!("Group created", hex::encode(&gid));

    // Add bob
    let (_commit, welcome) = mls_platform_api::mls_group_add(
        &mut state_alice,
        &gid,
        &alice_id,
        Some(group_config.clone()),
        vec![bob_kp],
    )?;

    mls_platform_api::mls_receive(
        &state_alice,
        &gid,
        &alice_id,
        MlsMessageOrAck::Ack,
        Some(group_config.clone()),
    )?;

    // Bob joins
    mls_platform_api::mls_group_join(
        &state_bob,
        &bob_id,
        welcome,
        Some(group_config.clone()),
        None,
    )?;

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_send(
        &state_bob,
        &gid,
        &bob_id,
        b"hello",
        Some(group_config.clone()),
    )?;

    let message = mls_platform_api::mls_receive(
        &state_alice,
        &gid,
        &alice_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
        Some(group_config.clone()),
    )?;

    dbg!(format!("{message:?}"));

    let members =
        mls_platform_api::mls_members(&state_alice, &alice_id, Some(group_config.clone()), &gid)?;

    dbg!(format!("{members:?}"));

    // Generate an exporter for the Group
    let exporter = mls_platform_api::mls_export(
        &state_alice,
        &gid,
        &alice_id,
        "exporter label".as_bytes(),
        "exporter context".as_bytes(),
        32,
        Some(group_config.clone()),
    )?;

    dbg!(format!("{exporter:?}"));

    Ok(())
}
