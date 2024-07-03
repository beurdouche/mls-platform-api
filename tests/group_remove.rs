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
// * Bob adds Charlie to the group
//   - Bob receives the add commit
//   - Alice receives the add commit
//   - Charlie joins the group
// * Charlie removes Alice from the group (group_remove)
//   - Charlie receives her remove commit
//   - Alice receives the remove commit
//   - Bob receives the remove commit

#[test]
fn test_group_remove() -> Result<(), PlatformError> {
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
        &MlsMessageOrAck::MlsMessage(commit_output.commit.clone()),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after adding bob): {members_str:?}");

    // Bob joins
    println!("\nBob joins the group created by Alice");
    mls_platform_api::mls_group_join(&state_global, &bob_id, &welcome, None)?;

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
    // println!("\nBob process their Commit");
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
    // Charlie removes Alice from the group
    //
    println!("\nCharlie removes Alice from the Group");
    let commit_output_3_bytes =
        mls_platform_api::mls_group_remove(&state_global, &gid, &charlie_id, &alice_id)?;

    let commit_3_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_3_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_3 = commit_3_output.commit;

    // Charlie receives the commit
    mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        &MlsMessageOrAck::Ack(gid.to_vec()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after removing alice): {members_str:?}");

    // Alice receives the commit from Charlie
    println!("\nAlice receives the remove commit from Charlie");
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;
    println!("Members (alice, after receiving alice's removal the group): {members_str:?}");
    println!("Alice's state for the group has been removed");

    // Bob receives the commit from Charlie
    println!("\nBob receives the remove commit from Charlie");
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        &MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after receiving alice's removal the group): {members_str:?}");

    // Parse the members list from JSON
    let members_list: mls_platform_api::MlsGroupMembers =
        serde_json::from_slice(&members).expect("Failed to parse members");

    // Check if Alice is still in the members list
    let alice_present = members_list
        .identities
        .iter()
        .any(|(id, _)| id == &alice_id);

    // Test that alice was removed from the group
    assert!(
        !alice_present,
        "Alice should not be in the group members after removal"
    );

    Ok(())
}
