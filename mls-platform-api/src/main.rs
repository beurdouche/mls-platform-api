// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use serde_json::from_slice;

fn main() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_alice = mls_platform_api::state_access("alice.db".into(), [0u8; 32])?;
    let mut state_bob = mls_platform_api::state_access("bob.db".into(), [0u8; 32])?;
    let mut state_charlie = mls_platform_api::state_access("charlie.db".into(), [0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;
    let charlie_cred = mls_platform_api::mls_generate_credential_basic("charlie")?;

    dbg!("Alice credential", hex::encode(&alice_cred));
    dbg!("Bob credential", hex::encode(&bob_cred));
    dbg!("Charlie credential", hex::encode(&charlie_cred));

    // Create signature keypairs and store them in the state
    let alice_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_alice,
        group_config.ciphersuite,
    )?;

    let bob_id =
        mls_platform_api::mls_generate_signature_keypair(&mut state_bob, group_config.ciphersuite)?;

    let charlie_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_charlie,
        group_config.ciphersuite,
    )?;

    dbg!("Alice identifier", hex::encode(&alice_id));
    dbg!("Bob identifier", hex::encode(&bob_id));
    dbg!("Charlie identifier", hex::encode(&charlie_id));

    // Create Key Package for Bob
    let bob_kp = mls_platform_api::mls_generate_key_package(
        &state_bob,
        bob_id.clone(),
        bob_cred,
        Default::default(),
    )?;

    // Create Key Package for Charlie
    let charlie_kp = mls_platform_api::mls_generate_key_package(
        &state_charlie,
        charlie_id.clone(),
        charlie_cred,
        Default::default(),
    )?;
    dbg!(format!("{charlie_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_alice,
        &alice_id,
        alice_cred,
        None,
        None,
        Default::default(),
    )?;

    dbg!("Group created", hex::encode(&gid));

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_alice, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, before adding bob): {members_str:?}");

    // Alice adds Bob to a group
    let commit_output_bytes =
        mls_platform_api::mls_group_add(&mut state_alice, &gid, &alice_id, vec![bob_kp])?;

    let commit_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_bytes).expect("Failed to deserialize MlsCommitOutput");

    let welcome = commit_output
        .welcome
        .first()
        .expect("No welcome messages found")
        .clone();

    mls_platform_api::mls_receive(&state_alice, &alice_id, MlsMessageOrAck::Ack(gid.to_vec()))?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_alice, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after adding bob): {members_str:?}");

    // Bob joins
    mls_platform_api::mls_group_confirm_join(&state_bob, &bob_id, welcome.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_alice, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after joining the group): {members_str:?}");

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_send(&state_bob, &gid, &bob_id, b"hello")?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_alice,
        &alice_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
    )?;
    dbg!(format!("{message:?}"));

    // Bob adds Charlie
    let commit_output_2_bytes =
        mls_platform_api::mls_group_add(&mut state_bob, &gid, &bob_id, vec![charlie_kp])?;

    let commit_2_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_2_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_2 = commit_2_output.commit;
    let welcome_2 = commit_2_output
        .welcome
        .first()
        .expect("No welcome messages found")
        .clone();

    mls_platform_api::mls_receive(&state_bob, &bob_id, MlsMessageOrAck::Ack(bob_id.to_vec()))?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_bob, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after adding charlie): {members_str:?}");

    // Alice receives the commit
    mls_platform_api::mls_receive(
        &state_alice,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_2),
    )?;

    // Charlie joins
    mls_platform_api::mls_group_confirm_join(&state_charlie, &charlie_id, welcome_2.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_charlie, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after joining the group): {members_str:?}");

    // Charlie removes Alice from the group
    let commit_output_3_bytes =
        mls_platform_api::mls_group_remove(&state_charlie, &gid, &charlie_id, &alice_id)?;

    let commit_3_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_3_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_3 = commit_3_output.commit;

    mls_platform_api::mls_receive(
        &state_charlie,
        &charlie_id,
        MlsMessageOrAck::Ack(gid.to_vec()),
    )?;

    let members = mls_platform_api::mls_members(&state_charlie, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after removing alice): {members_str:?}");

    // Alice receives the commit from Charlie
    let _ = mls_platform_api::mls_receive(
        &state_alice,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_members(&state_bob, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after receiving alice's removal the group): {members_str:?}");
    // TODO: Alice should probably delete the group from the state before this point

    // Bob receives the commit from Charlie
    let _ = mls_platform_api::mls_receive(
        &state_bob,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_members(&state_bob, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after receiving alice's removal the group): {members_str:?}");

    // Generate an exporter for the Group
    let exporter = mls_platform_api::mls_export(
        &state_alice,
        &gid,
        &alice_id,
        "exporter label".as_bytes(),
        "exporter context".as_bytes(),
        32,
    )?;
    let exporter_str = mls_platform_api::utils_json_bytes_to_string_custom(&exporter)?;
    println!("Exporter: {exporter_str:?}");

    Ok(())
}
