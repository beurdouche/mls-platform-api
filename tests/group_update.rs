// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::ClientConfig;
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
// * Bob produces group update with group info (group_update with external join)
//   - Bob receives his update commit
//   - Alice receives his update commit
// * Diana sends a commit to do an external join (group_update for external join)
//   - Alice receives the commit
//   - Bob receives the commit

#[test]
fn test_group_external_join() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db", &[0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;
    let diana_cred = mls_platform_api::mls_generate_credential_basic("diana")?;

    println!("\nAlice credential: {}", hex::encode(&alice_cred));
    println!("Bob credential: {}", hex::encode(&bob_cred));
    println!("Diana credential: {}", hex::encode(&diana_cred));

    // Create signature keypairs and store them in the state
    let alice_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    let diana_id =
        mls_platform_api::mls_generate_signature_keypair(&state_global, group_config.ciphersuite)?;

    println!("\nAlice identifier: {}", hex::encode(&alice_id));
    println!("Bob identifier: {}", hex::encode(&bob_id));
    println!("Diana identifier: {}", hex::encode(&diana_id));

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
    // Bob produces group info to allow an external join from Diana
    //
    let client_config = ClientConfig {
        allow_external_commits: true,
        ..Default::default()
    };

    println!("\nBob produce a group info so that someone can do an External join");
    let commit_4_output = mls_platform_api::mls_group_update(
        &mut state_global,
        &gid,
        &bob_id,
        None,
        None,
        None,
        &client_config,
    )?;

    let commit_4_output: mls_platform_api::MlsCommitOutput = from_slice(&commit_4_output).unwrap();

    // Alice receives Bob's commit
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(commit_4_output.commit.clone()),
    )?;

    let members_alice_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_alice_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_alice_bytes)?;
    println!(
        "Members (alice, after receiving the commit allowing external join): {members_alice_str:?}"
    );

    // Bob receives own commit
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        &MlsMessageOrAck::MlsMessage(commit_4_output.commit.clone()),
    )?;

    let members_bob_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_bob_str = mls_platform_api::utils_json_bytes_to_string_custom(&members_bob_bytes)?;
    println!("Members (bob, after commit allowing external join): {members_bob_str:?}");

    //
    // Diana joins the group with an external commit
    //
    println!("\nDiana uses the group info created by Bob to do an External join");
    let external_commit_output_bytes = mls_platform_api::mls_group_external_commit(
        &state_global,
        &diana_id,
        &diana_cred,
        &commit_4_output
            .group_info
            .expect("alice should produce group info"),
        // use tree in extension for now
        None,
    )?;

    let external_commit_output: mls_platform_api::MlsExternalCommitOutput =
        serde_json::from_slice(&external_commit_output_bytes).unwrap();

    println!("Externally joined group {:?}", &external_commit_output.gid);

    let members_diana_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &diana_id)?;
    let members_diana_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_diana_bytes)?;
    println!("Members (diane, after joining): {members_diana_str:?}");

    // Alice receives Diana's commit
    println!("\nAlice receives the External Join from Diana");
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        &MlsMessageOrAck::MlsMessage(external_commit_output.external_commit.clone()),
    )?;

    let members_alice_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &alice_id)?;
    let members_alice_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&members_alice_bytes)?;
    println!("Members (alice, after receiving the commit from Diana): {members_alice_str:?}");

    // Bob receives Diana's commit
    println!("\nBob receives the External Join from Diana");
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        &MlsMessageOrAck::MlsMessage(external_commit_output.external_commit.clone()),
    )?;

    let members_bob_bytes = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_bob_str = mls_platform_api::utils_json_bytes_to_string_custom(&members_bob_bytes)?;
    println!("Members (bob, after receiving the commit from Diana): {members_bob_str:?}");

    // Parse the members list from JSON
    let members_diana_json: mls_platform_api::MlsGroupMembers =
        serde_json::from_slice(&members_diana_bytes).expect("Failed to parse members");

    // Check if Diana is in the members list
    let diana_present = members_diana_json
        .identities
        .iter()
        .any(|(id, _)| id == &diana_id);

    // Test that alice was removed from the group
    assert!(
        diana_present,
        "Diana should be in the group members after external join"
    );

    // Test that membership are all the same
    assert!(members_alice_bytes == members_bob_bytes);
    assert!(members_diana_bytes == members_bob_bytes);

    Ok(())
}
