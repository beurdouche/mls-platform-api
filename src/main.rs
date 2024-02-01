use mls_rs::error::MlsError;

const CIPHERSUITE: mls_platform_api::CipherSuite =
    // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    mls_platform_api::CipherSuite::CURVE25519_AES128;

const VERSION: mls_rs::ProtocolVersion = mls_rs::ProtocolVersion::MLS_10;

fn main() -> Result<(), MlsError> {
    let group_config =
        mls_platform_api::mls_create_group_config(CIPHERSUITE, VERSION, Default::default())
            .unwrap();
    let mut state_alice = mls_platform_api::create_state();

    // Create signature keypair for Alice
    let alice_signing_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        "alice",
        CIPHERSUITE,
        None,
    )
    .unwrap();

    // Create key package for Alice
    let _alice_kp = mls_platform_api::generate_key_package(
        &state_alice,
        alice_signing_id.clone(),
        Some(group_config.clone()),
        None,
    )
    .unwrap();

    dbg!(format!("{alice_signing_id:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_create_group(
        &mut state_alice,
        Some(group_config),
        None,
        alice_signing_id.clone(),
    )
    .unwrap();

    dbg!("group created", hex::encode(&gid));

    let _message =
        mls_platform_api::mls_update(gid, &mut state_alice, alice_signing_id, None).unwrap();

    dbg!("updated");

    // Generate the exported state for Alice
    let _exported_state = state_alice.to_bytes().unwrap();

    Ok(())
}

// // Create clients for Alice and Bob
// let alice = make_client(crypto_provider.clone(), "alice")?;
// let bob = make_client(crypto_provider.clone(), "bob")?;

// // Alice creates a new group.
// let mut alice_group = alice.create_group(ExtensionList::default())?;

// // Bob generates a key package that Alice needs to add Bob to the group.
// let bob_key_package = bob.generate_key_package_message()?;

// // Alice issues a commit that adds Bob to the group.
// let mut alice_commit = alice_group
//     .commit_builder()
//     .add_member(bob_key_package)?
//     .build()?;

// // Alice confirms that the commit was accepted by the group so it can be applied locally.
// // This would normally happen after a server confirmed your commit was accepted and can
// // be broadcasted.
// alice_group.apply_pending_commit()?;

// // Bob joins the group with the welcome message created as part of Alice's commit.
// let (mut bob_group, _) = bob.join_group(None, alice_commit.welcome_messages.pop().unwrap())?;

// // Alice encrypts an application message to Bob.
// let msg = alice_group.encrypt_application_message(b"hello world", Default::default())?;

// // Bob decrypts the application message from Alice.
// let msg = bob_group.process_incoming_message(msg)?;

// println!("Received message: {:?}", msg);

// // Alice and bob write the group state to their configured storage engine
// alice_group.write_to_storage()?;
// bob_group.write_to_storage()?;
