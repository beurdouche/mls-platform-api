// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::mls_group_propose_remove;
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
// * Bob sends a self remove proposal to the group (group_propose_remove)
//   - Charlie receives the proposal (receive for proposal)
// * Charlie produces the commit for the remove proposal
//   - Alice receives her remove commit
//   - Charlie receives her remove commit
//   - Bob receives her remove commit

#[test]
fn test_group_propose_self_remove() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db".into(), [0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;
    let charlie_cred = mls_platform_api::mls_generate_credential_basic("charlie")?;

    println!("\nAlice credential: {}", hex::encode(&alice_cred));
    println!("Bob credential: {}", hex::encode(&bob_cred));
    println!("Charlie credential: {}", hex::encode(&charlie_cred));

    // Create signature keypairs and store them in the state
    let alice_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_global,
        group_config.ciphersuite,
    )?;

    let bob_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_global,
        group_config.ciphersuite,
    )?;

    let charlie_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_global,
        group_config.ciphersuite,
    )?;

    println!("\nAlice identifier: {}", hex::encode(&alice_id));
    println!("Bob identifier: {}", hex::encode(&bob_id));
    println!("Charlie identifier: {}", hex::encode(&charlie_id));

    // Create Key Package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &state_global,
        bob_id.clone(),
        bob_cred,
        Default::default(),
    )?;

    // Create Key Package for Charlie
    let charlie_kp = mls_platform_api::mls_generate_key_package(
        &state_global,
        charlie_id.clone(),
        charlie_cred,
        Default::default(),
    )?;

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_global,
        &alice_id,
        alice_cred,
        None,
        None,
        Default::default(),
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
        MlsMessageOrAck::MlsMessage(commit_output.commit.clone()),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after adding bob): {members_str:?}");

    // Bob joins
    println!("\nBob joins the group created by Alice");
    mls_platform_api::mls_group_join(&state_global, &bob_id, welcome.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after joining the group): {members_str:?}");

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
        MlsMessageOrAck::MlsMessage(commit_2.clone()),
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
        MlsMessageOrAck::MlsMessage(commit_2),
    )?;

    // Charlie joins
    println!("\nCharlie joins the group");
    mls_platform_api::mls_group_join(&state_global, &charlie_id, welcome_2.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after joining the group): {members_str:?}");

    //
    // Bob proposes to remove itself
    //
    println!("\nBob proposes a self remove");
    let self_remove_proposal = mls_group_propose_remove(&state_global, &gid, &bob_id, &bob_id)?;

    //
    // Charlie receives the proposal from Bob
    //
    println!("\nCharlie commits to the remove");
    let commit_5_output_bytes = mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        MlsMessageOrAck::MlsMessage(self_remove_proposal),
    )?;

    let commit_5_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_5_output_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_5_msg = MlsMessageOrAck::MlsMessage(commit_5_output.commit);

    // Alice processes the remove commit
    println!("\nAlice processes the remove commit");
    mls_platform_api::mls_receive(&state_global, &alice_id, commit_5_msg.clone())?;

    let members_alice_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_alice_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_alice_bytes)?;
    println!("Members (alice, after removing Bob): {members_alice_str:?}");

    // Charlie processes the remove commit
    println!("\nCharlie processes the remove commit");
    mls_platform_api::mls_receive(&state_global, &charlie_id, commit_5_msg.clone())?;

    let members_charlie_bytes =
        mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_charlie_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_charlie_bytes)?;
    println!("Members (charlie, after removing bob): {members_charlie_str:?}");

    // Bob processes the remove commit
    println!("\nBob processes the remove commit");
    let out_commit_5_bob = mls_platform_api::mls_receive(&state_global, &bob_id, commit_5_msg)?;
    let out_commit_5_bob_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&out_commit_5_bob)?;

    println!("Bob, out_commit_5 {out_commit_5_bob_str:?}");
    println!("Bob's state for the group has been removed");
    // Note: Bob cannot look at its own group state because it was already removed

    // Parse the members list from JSON
    let members_alice_json: mls_platform_api::MlsGroupMembers =
        serde_json::from_slice(&members_alice_bytes).expect("Failed to parse members");

    // Check if Bob is present in the group
    let bob_present = members_alice_json
        .identities
        .iter()
        .any(|(id, _)| id == &bob_id);

    // Test that bob was removed from the group
    assert!(
        !bob_present,
        "Bob should not be in the group members after removal"
    );

    // Test that Alice and Charlie have the same group
    assert!(members_alice_bytes == members_charlie_bytes);

    Ok(())
}
