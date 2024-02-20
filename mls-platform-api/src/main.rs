use mls_platform_api::MlsError;
use mls_platform_api::MlsMessageOrAck;

fn main() -> Result<(), MlsError> {
    let group_config = mls_platform_api::GroupConfig::default();

    let mut state_alice = mls_platform_api::state("alice".into(), [0u8; 32])?;
    let mut state_bob = mls_platform_api::state("bob".into(), [0u8; 32])?;

    // Create signature keypairs
    let alice_signing_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        "alice",
        group_config.ciphersuite,
        None,
    )?;

    dbg!(String::from_utf8(alice_signing_id.clone()).unwrap());

    // Alice's key is stored in the DB
    /*let alice_signing_id = SigningIdentity::new(
        BasicCredential::new(b"alice".into()).into_credential(),
        hex::decode("0f210723849278dfa71dab150343cdf471f80dc097dca57c91f096a3c50c2f1b")
            .unwrap()
            .into(),
    );*/

    let bob_signing_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_bob,
        "bob",
        group_config.ciphersuite,
        None,
    )?;

    // Create key package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &state_bob,
        bob_signing_id.clone(),
        Some(group_config.clone()),
        None,
    )?;

    dbg!(format!("{bob_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_alice,
        Some(group_config.clone()),
        None,
        &alice_signing_id,
    )?;

    dbg!("group created", hex::encode(&gid));

    // Add bob
    let (_commit, welcome) = mls_platform_api::mls_group_add(
        &mut state_alice,
        &gid,
        Some(group_config.clone()),
        vec![bob_kp],
        &alice_signing_id,
    )?;

    mls_platform_api::mls_receive(
        &state_alice,
        &gid,
        &alice_signing_id,
        MlsMessageOrAck::Ack,
        Some(group_config.clone()),
    )?;

    // Bob joins
    mls_platform_api::mls_group_join(
        &state_bob,
        &bob_signing_id,
        Some(group_config.clone()),
        welcome,
        None,
    )?;

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_send(
        &state_bob,
        &gid,
        &bob_signing_id,
        Some(group_config.clone()),
        b"hello",
    )?;

    let message = mls_platform_api::mls_receive(
        &state_alice,
        &gid,
        &alice_signing_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
        Some(group_config.clone()),
    )?;

    dbg!(format!("{message:?}"));

    let members =
        mls_platform_api::mls_members(&state_alice, &alice_signing_id, Some(group_config), &gid)?;

    dbg!(format!("{members:?}"));

    // Generate the exported state for Alice
    //let _exported_state = state_alice.to_bytes().unwrap();

    Ok(())
}
