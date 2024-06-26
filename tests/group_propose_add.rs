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
// * Bob propose to add Charlie to the group
//   - Alice receives the proposal
// * Alice adds Charlie to the group
//   - Bob receives the add commit
//   - Alice receives the add commit
//   - Charlie joins the group

#[test]
fn test_propose_add() -> Result<(), PlatformError> {
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
    // Bob propose to add Charlie
    //
    println!("\nBob proposes to add Charlie to the Group");
    let proposals_add_bytes = mls_platform_api::mls_group_propose_add(
        &mut state_global,
        &gid,
        &bob_id,
        vec![charlie_kp],
    )?;

    let proposal_add_bytes = proposals_add_bytes.first().unwrap();

    // Alice receives the Add proposal and commits to it
    println!("\nAlice commits to the add");
    let commit_5_output_bytes = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(proposal_add_bytes.clone()),
    )?;

    let commit_5_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_5_output_bytes).expect("Failed to deserialize MlsCommitOutput");

    // Bobs process the commit
    println!("\nBob receives the commit");
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_5_output.commit.clone()),
    )?;

    // List the members of the group
    let members_bob_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_bob_str = mls_platform_api::utils_json_bytes_to_string_custom(&members_bob_bytes)?;
    println!("Members (bob, after adding charlie): {members_bob_str:?}");

    // Alice receives the commit
    println!("\nAlice receives the commit");
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_5_output.commit),
    )?;

    // List the members of the group
    let members_alice_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_alice_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_alice_bytes)?;
    println!("Members (alice, after adding charlie): {members_alice_str:?}");

    // Extract the welcome from the commit output
    let welcome_5 = commit_5_output
        .welcome
        .first()
        .expect("No welcome messages found")
        .clone();

    // Charlie joins
    println!("\nCharlie joins the group");
    mls_platform_api::mls_group_join(&state_global, &charlie_id, welcome_5.clone(), None)?;

    // List the members of the group
    let members_charlie_bytes =
        mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_charlie_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_charlie_bytes)?;
    println!("Members (charlie, after joining the group): {members_charlie_str:?}");

    // Test that Alice, Bob and Charlie are in the same group
    assert!(members_alice_bytes == members_bob_bytes);
    assert!(members_bob_bytes == members_charlie_bytes);

    Ok(())
}
