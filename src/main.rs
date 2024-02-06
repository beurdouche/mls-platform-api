use mls_platform_api::MlsMessageOrAck;
use mls_rs::{
    error::MlsError,
    identity::{basic::BasicCredential, SigningIdentity},
};

const CIPHERSUITE: mls_platform_api::CipherSuite =
    // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    mls_platform_api::CipherSuite::CURVE25519_AES128;

const VERSION: mls_rs::ProtocolVersion = mls_rs::ProtocolVersion::MLS_10;

fn main() -> Result<(), MlsError> {
    let group_config =
        mls_platform_api::mls_create_group_config(CIPHERSUITE, VERSION, Default::default())
            .unwrap();

    let mut state_alice = mls_platform_api::create_state("sqlite/alice".into());
    let mut state_bob = mls_platform_api::create_state("sqlite/bob".into());

    // Create signature keypairs
    let alice_signing_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        "alice",
        CIPHERSUITE,
        None,
    )
    .unwrap();

    dbg!(hex::encode(&alice_signing_id.signature_key));

    // Alice's key is stored in the DB
    /*let alice_signing_id = SigningIdentity::new(
        BasicCredential::new(b"alice".into()).into_credential(),
        hex::decode("0f210723849278dfa71dab150343cdf471f80dc097dca57c91f096a3c50c2f1b")
            .unwrap()
            .into(),
    );*/

    let bob_signing_id =
        mls_platform_api::mls_generate_signature_keypair(&mut state_bob, "bob", CIPHERSUITE, None)
            .unwrap();

    // Create key package for Bob
    let bob_kp = mls_platform_api::generate_key_package(
        &state_bob,
        bob_signing_id.clone(),
        Some(group_config.clone()),
        None,
    )
    .unwrap();

    dbg!(format!("{bob_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_create_group(
        &mut state_alice,
        Some(group_config.clone()),
        None,
        alice_signing_id.clone(),
    )
    .unwrap();

    dbg!("group created", hex::encode(&gid));

    // Add bob
    let (_commit, welcome) = mls_platform_api::mls_add_user(
        &mut state_alice,
        &gid,
        Some(group_config.clone()),
        vec![bob_kp],
        alice_signing_id.clone(),
    )
    .unwrap();

    mls_platform_api::mls_process_received_message(
        &state_alice,
        &gid,
        alice_signing_id.clone(),
        MlsMessageOrAck::Ack,
        Some(group_config.clone()),
    )
    .unwrap();

    // Bob joins
    mls_platform_api::mls_process_received_join_message(
        &state_bob,
        bob_signing_id.clone(),
        Some(group_config.clone()),
        welcome,
        None,
    )
    .unwrap();

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_encrypt_message(
        &state_bob,
        &gid,
        bob_signing_id,
        Some(group_config.clone()),
        b"hello",
    )
    .unwrap();

    let message = mls_platform_api::mls_process_received_message(
        &state_alice,
        &gid,
        alice_signing_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
        Some(group_config),
    )
    .unwrap();

    dbg!(format!("{message:?}"));

    // Generate the exported state for Alice
    //let _exported_state = state_alice.to_bytes().unwrap();

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
