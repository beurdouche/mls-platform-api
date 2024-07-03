// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use serde_json::from_slice;

//
// Scenario
//
// * Alice, Bob, Charlie and Diana create signing identity (generate_signature_keypair)
// * Alice, Bob, Charlie and Diana create credentials (generate_credential_basic)
// * Bob and Charlie create key packages (generate_key_package)
// * Alice creates a group (group_create)
// * Alice adds Bob to the group (group_add)
//   - Alice receives her add commit (receive for commit)
//   - Bob joins the group (group_join)
// * Bob sends an application message (send)
//   - Alice receives the application message (receive for application message)

#[test]
fn test_send_receive() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db", &[0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice".as_bytes())?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob".as_bytes())?;

    println!("\nAlice credential: {}", hex::encode(&alice_cred));
    println!("Bob credential: {}", hex::encode(&bob_cred));

    // Create signature keypairs and store them in the state
    let alice_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    println!("\nAlice identifier: {}", hex::encode(&alice_id));
    println!("Bob identifier: {}", hex::encode(&bob_id));

    // Create Key Package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &state_global,
        &bob_id,
        &bob_cred,
        &Default::default(),
    )?;

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_global,
        &alice_id,
        &alice_cred,
        None,
        None,
        &Default::default(),
    )?;

    println!("\nGroup created by Alice: {}", hex::encode(&gid));

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, before adding bob): {members_str:?}");

    //
    // Alice adds Bob to a group
    //
    println!("\nAlice adds Bob to the Group");
    let commit_output_bytes =
        mls_platform_api::mls_group_add(&mut state_global, &gid, &alice_id, vec![bob_kp])?;

    let commit_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_bytes).expect("Failed to deserialize MlsCommitOutput");

    let welcome = commit_output
        .welcome
        .first()
        .expect("No welcome messages found")
        .clone();

    // Alice process her own commit
    // println!("\nAlice process her commit to add Bob to the Group");
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(commit_output.commit.clone()),
    )?;

    // Bob joins
    println!("\nBob joins the group created by Alice");
    mls_platform_api::mls_group_join(&state_global, &bob_id, &welcome, None)?;

    //
    // Bob sends message to alice
    //
    println!("\nBob sends a message to Alice");
    let message_str = "hello";
    let ciphertext =
        mls_platform_api::mls_send(&state_global, &gid, &bob_id, message_str.as_bytes())?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(ciphertext),
    )?;

    let message_2_str = String::from_utf8(message.clone()).unwrap();
    println!("\nAlice receives the message from Bob {:?}", message_2_str);

    assert!(message_str == message_2_str);
    Ok(())
}
