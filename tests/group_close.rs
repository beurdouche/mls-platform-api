// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use serde_json::from_slice;

//
// Scenario
//
// * Alice, Bob, Charlie create signing identity (generate_signature_keypair)
// * Alice, Bob, Charlie create credentials (generate_credential_basic)
// * Bob and Charlie create key packages (generate_key_package)
// * Alice creates a group (group_create)
// * Alice adds Bob to the group (group_add)
//   - Alice receives her add commit (receive for commit)
//   - Bob joins the group (group_join)
// * Bob adds Charlie to the group
//   - Bob receives the add commit
//   - Alice receives the add commit
//   - Charlie joins the group
// * Charlie decides that it's enough and closes the group (group_close)
//   - Alice processes the close commit
//   - Bob processes the close commit
//   - Charlie processes the close commit
// * Charlie removes her state for the group (state_delete_group)

#[test]
fn test_group_close() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db", &[0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice".as_bytes())?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob".as_bytes())?;
    let charlie_cred = mls_platform_api::mls_generate_credential_basic("charlie".as_bytes())?;

    println!("\nAlice credential: {}", hex::encode(&alice_cred));
    println!("Bob credential: {}", hex::encode(&bob_cred));
    println!("Charlie credential: {}", hex::encode(&charlie_cred));

    // Create signature keypairs and store them in the state
    let alice_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    let charlie_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    println!("\nAlice identifier: {}", hex::encode(&alice_id));
    println!("Bob identifier: {}", hex::encode(&bob_id));
    println!("Charlie identifier: {}", hex::encode(&charlie_id));

    // Create Key Package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &state_global,
        &bob_id,
        &bob_cred,
        &Default::default(),
    )?;

    // Create Key Package for Charlie
    let charlie_kp = mls_platform_api::mls_generate_key_package(
        &state_global,
        &charlie_id,
        &charlie_cred,
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
    println!("\nAlice process her commit to add Bob to the Group");
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(commit_output.commit),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after adding bob): {members_str:?}");

    // Bob joins
    println!("\nBob joins the group created by Alice");
    mls_platform_api::mls_group_join(&state_global, &bob_id, &welcome, None)?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after joining the group): {members_str:?}");

    //
    // Bob sends message to alice
    //
    println!("\nBob sends a message to Alice");
    let ciphertext = mls_platform_api::mls_send(&state_global, &gid, &bob_id, b"hello")?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(ciphertext),
    )?;
    println!(
        "\nAlice receives the message from Bob {:?}",
        String::from_utf8(message).unwrap()
    );

    //
    // Bob adds Charlie
    //
    println!("\nBob adds Charlie to the Group");
    let commit_output_2_bytes =
        mls_platform_api::mls_group_add(&mut state_global, &gid, &bob_id, vec![charlie_kp])?;

    let commit_2_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_2_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_2 = commit_2_output.commit;
    let welcome_2 = commit_2_output
        .welcome
        .first()
        .expect("No welcome messages found")
        .clone();

    // Bobs process its commit
    println!("\nBob process their Commit");
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        &MlsMessageOrAck::MlsMessage(commit_2.clone()),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after adding charlie): {members_str:?}");

    // Alice receives the commit
    println!("\nAlice receives the commit from Bob to add Charlie");
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(commit_2),
    )?;

    // Charlie joins
    println!("\nCharlie joins the group");
    mls_platform_api::mls_group_join(&state_global, &charlie_id, &welcome_2, None)?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after joining the group): {members_str:?}");

    //
    // Charlie decides to close the group
    //
    println!("\nCharlie decides that it's enough and closes the group");
    let commit_output_6_bytes =
        mls_platform_api::mls_group_close(&state_global, &gid, &charlie_id)?;

    let commit_6_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_6_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_6_msg = MlsMessageOrAck::MlsMessage(commit_6_output.commit);

    // Alice processes the close commit
    println!("\nAlice processes the close commit");
    let out_alice_bytes = mls_platform_api::mls_receive(&state_global, &alice_id, &commit_6_msg)?;
    let out_alice_str = mls_platform_api::utils_json_bytes_to_string_custom(&out_alice_bytes)?;

    println!("Alice, out_alice_str {out_alice_str:?}");
    println!("Alice's state for the group has been removed");
    // Note: Alice cannot look at its own group state because it was already removed

    // Bob processes the close commit
    println!("\nBob processes the close commit");
    let out_bob_bytes = mls_platform_api::mls_receive(&state_global, &bob_id, &commit_6_msg)?;
    let out_bob_str = mls_platform_api::utils_json_bytes_to_string_custom(&out_bob_bytes)?;

    println!("Bob, out_bob_str {out_bob_str:?}");
    println!("Bob's state for the group has been removed");
    // Note: Bob cannot look at its own group state because it was already removed

    // Charlie processes the close commit
    println!("\nCharlie processes the close commit");
    mls_platform_api::mls_receive(&state_global, &charlie_id, &commit_6_msg)?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after processing their group_close commit): {members_str:?}");

    // Charlie deletes her state for the group
    println!("\nCharlie deletes her state");
    let out_charlie_bytes = mls_platform_api::state_delete_group(&state_global, &gid, &charlie_id)?;
    let out_charlie_str = mls_platform_api::utils_json_bytes_to_string_custom(&out_charlie_bytes)?;

    println!("Charlie, group deletion confirmation {out_charlie_str:?}");

    // Test that Alice, Bob and Charlie have closed their group
    // (checks the group id and epoch are equals)
    assert!(out_alice_bytes == out_bob_bytes);
    assert!(out_bob_bytes == out_charlie_bytes);

    Ok(())
}
