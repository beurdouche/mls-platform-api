// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::ClientConfig;
use mls_platform_api::MlsMessageOrAck;
use mls_platform_api::PlatformError;

use serde_json::from_slice;

fn main() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db".into(), [0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;
    let charlie_cred = mls_platform_api::mls_generate_credential_basic("charlie")?;

    dbg!("Alice credential", hex::encode(&alice_cred));
    dbg!("Bob credential", hex::encode(&bob_cred));
    dbg!("Charlie credential", hex::encode(&charlie_cred));

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

    dbg!("Alice identifier", hex::encode(&alice_id));
    dbg!("Bob identifier", hex::encode(&bob_id));
    dbg!("Charlie identifier", hex::encode(&charlie_id));

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
    dbg!(format!("{charlie_kp:?}"));

    // Create a group with Alice
    let gid = mls_platform_api::mls_group_create(
        &mut state_global,
        &alice_id,
        alice_cred,
        None,
        None,
        Default::default(),
    )?;

    dbg!("Group created", hex::encode(&gid));

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, before adding bob): {members_str:?}");

    // Alice adds Bob to a group
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
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_output.commit.clone()),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after adding bob): {members_str:?}");

    // Bob joins
    mls_platform_api::mls_group_confirm_join(&state_global, &bob_id, welcome.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_global, &gid, &alice_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after joining the group): {members_str:?}");

    // Bob sends message to alice
    let ciphertext = mls_platform_api::mls_send(&state_global, &gid, &bob_id, b"hello")?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
    )?;
    dbg!(format!("{message:?}"));

    // Bob adds Charlie
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
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_2.clone()),
    )?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after adding charlie): {members_str:?}");

    // Alice receives the commit
    mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_2),
    )?;

    // Charlie joins
    mls_platform_api::mls_group_confirm_join(&state_global, &charlie_id, welcome_2.clone(), None)?;

    // List the members of the group
    let members = mls_platform_api::mls_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after joining the group): {members_str:?}");

    // Charlie removes Alice from the group
    let commit_output_3_bytes =
        mls_platform_api::mls_group_remove(&state_global, &gid, &charlie_id, &alice_id)?;

    let commit_3_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_3_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_3 = commit_3_output.commit;

    mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        MlsMessageOrAck::Ack(gid.to_vec()),
    )?;

    let members = mls_platform_api::mls_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after removing alice): {members_str:?}");

    // Alice receives the commit from Charlie
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (alice, after receiving alice's removal the group): {members_str:?}");
    // TODO: Alice should probably delete the group from the state before this point

    // Bob receives the commit from Charlie
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after receiving alice's removal the group): {members_str:?}");

    // Generate an exporter for the Group
    let exporter = mls_platform_api::mls_export(
        &state_global,
        &gid,
        &alice_id,
        "exporter label".as_bytes(),
        "exporter context".as_bytes(),
        32,
    )?;
    let exporter_str = mls_platform_api::utils_json_bytes_to_string_custom(&exporter)?;
    println!("Exporter: {exporter_str:?}");

    // Diana joins externally
    let diana_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_global,
        group_config.ciphersuite,
    )?;

    let diana_cred = mls_platform_api::mls_generate_credential_basic("diana")?;

    dbg!("Diana identifier", hex::encode(&diana_id));

    let mut client_config = ClientConfig::default();
    client_config.allow_external_commits = true;

    // Bob produces group info
    let commit_4_output = mls_platform_api::mls_group_update(
        &mut state_global,
        gid.clone(),
        bob_id.clone(),
        None,
        None,
        None,
        client_config,
    )?;

    let commit_4_output: mls_platform_api::MlsGroupUpdate = from_slice(&commit_4_output).unwrap();

    // Bob receives own commit
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_4_output.commit_output.commit),
    )?;

    // Diana joins and sends a message
    let external_commit_output_bytes = mls_platform_api::mls_group_external_commit(
        &state_global,
        diana_id.clone(),
        diana_cred,
        commit_4_output
            .commit_output
            .group_info
            .expect("alice should produce group info"),
        // use tree in extension for now
        None,
    )?;

    let external_commit_output: mls_platform_api::MlsExternalCommitOutput =
        serde_json::from_slice(&external_commit_output_bytes).unwrap();

    println!("externally joined group {:?}", &external_commit_output.gid);

    let ctx = mls_platform_api::mls_send(&state_global, &gid, &diana_id, b"hello from diana")?;

    // Bob receives Diana's commit and message
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(external_commit_output.external_commit),
    )?;

    let ptx =
        mls_platform_api::mls_receive(&state_global, &bob_id, MlsMessageOrAck::MlsMessage(ctx))?;

    println!("bob received message {:?}", String::from_utf8(ptx).unwrap());

    Ok(())
}
