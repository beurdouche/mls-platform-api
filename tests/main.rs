// Copyright (c) 2024 Mozilla Corporation and contributors.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_platform_api::mls_group_propose_remove;
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
// * Bob adds Charlie to the group
//   - Bob receives the add commit
//   - Alice receives the add commit
//   - Charlie joins the group
// * Charlie removes Alice from the group (group_remove)
//   - Charlie receives her remove commit
//   - Alice receives the remove commit
//   - Bob receives the remove commit
// * Bob produces group update with group info (group_update with external join)
//   - Bob receives his update commit
//   - Charlie receives the commit
// * Diana sends a commit to do an external join (group_update for external join)
// * Diana sends an application message
//   - Bob receives the commit
//   - Bob receives Diana's application message
//   - Charlie receives the commit
//   - Charlie receives Diana's application message
// * Bob sends a self remove proposal to the group (group_propose_remove)
//   - Diana receives the proposal (receive for proposal)
// * Diana produces the commit for the remove proposal
//   - Diana receives her remove commit
//   - Charlie receives her remove commit
//   - Bob receives her remove commit
// * Charlie decides that it's enough and closes the group (group_close)
//   - Diana processes the close commit
//   - Charlie processes the close commit
// * Charlie removes her state for the group (state_delete_group)

#[test]
fn main() -> Result<(), PlatformError> {
    // Default group configuration
    let group_config = mls_platform_api::GroupConfig::default();

    // Storage states
    let mut state_global = mls_platform_api::state_access("global.db".into(), [0u8; 32])?;

    // Credentials
    let alice_cred = mls_platform_api::mls_generate_credential_basic("alice")?;
    let bob_cred = mls_platform_api::mls_generate_credential_basic("bob")?;
    let charlie_cred = mls_platform_api::mls_generate_credential_basic("charlie")?;
    let diana_cred = mls_platform_api::mls_generate_credential_basic("diana")?;

    println!("\nAlice credential: {}", hex::encode(&alice_cred));
    println!("Bob credential: {}", hex::encode(&bob_cred));
    println!("Charlie credential: {}", hex::encode(&charlie_cred));
    println!("Diana credential: {}", hex::encode(&diana_cred));

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

    let diana_id = mls_platform_api::mls_generate_signature_keypair(
        &mut state_global,
        group_config.ciphersuite,
    )?;

    println!("\nAlice identifier: {}", hex::encode(&alice_id));
    println!("Bob identifier: {}", hex::encode(&bob_id));
    println!("Charlie identifier: {}", hex::encode(&charlie_id));
    println!("Diana identifier: {}", hex::encode(&diana_id));

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
    // Bob sends message to alice
    //
    println!("\nBob sends a message to Alice");
    let ciphertext = mls_platform_api::mls_send(&state_global, &gid, &bob_id, b"hello")?;

    // Alice receives the message
    let message = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(ciphertext),
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
        MlsMessageOrAck::Ack(gid.to_vec()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after removing alice): {members_str:?}");

    // Alice receives the commit from Charlie
    println!("\nAlice receives the remove commit from Charlie");
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &alice_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;
    println!("Members (alice, after receiving alice's removal the group): {members_str:?}");
    println!("Alice's state for the group has been removed");

    // Bob receives the commit from Charlie
    println!("\nBob receives the remove commit from Charlie");
    let _ = mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_3.clone()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after receiving alice's removal the group): {members_str:?}");

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
        gid.clone(),
        bob_id.clone(),
        None,
        None,
        None,
        client_config,
    )?;

    let commit_4_output: mls_platform_api::MlsCommitOutput = from_slice(&commit_4_output).unwrap();

    // Bob receives own commit
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(commit_4_output.commit.clone()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after commit allowing external join): {members_str:?}");

    // Charlie receives Bob's commit with GroupInfo for External Join
    mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        MlsMessageOrAck::MlsMessage(commit_4_output.commit),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after bob's commit allowing external join): {members_str:?}");

    //
    // Diana joins the group with an external commit
    //
    println!("\nDiana uses the group info created by Bob to do an External join");
    let external_commit_output_bytes = mls_platform_api::mls_group_external_commit(
        &state_global,
        diana_id.clone(),
        diana_cred,
        commit_4_output
            .group_info
            .expect("alice should produce group info"),
        // use tree in extension for now
        None,
    )?;

    let external_commit_output: mls_platform_api::MlsExternalCommitOutput =
        serde_json::from_slice(&external_commit_output_bytes).unwrap();

    println!("Externally joined group {:?}", &external_commit_output.gid);

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &diana_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (diane, after joining): {members_str:?}");

    //
    // Diana sends a message to the group
    //
    println!("\nDiana sends a message to the group");
    let ctx = mls_platform_api::mls_send(&state_global, &gid, &diana_id, b"hello from diana")?;

    // Bob receives Diana's commit
    println!("\nBob receives the External Join from Diana");
    mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(external_commit_output.external_commit.clone()),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &diana_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (bob, after diane joined externally): {members_str:?}");

    // Bob receives Diana's application message
    let ptx = mls_platform_api::mls_receive(
        &state_global,
        &bob_id,
        MlsMessageOrAck::MlsMessage(ctx.clone()),
    )?;

    println!(
        "\nBob receives Diana's message {:?}",
        String::from_utf8(ptx).unwrap()
    );

    // Charlie receives Diana's commit
    println!("\nCharlie receives the External Join from Diana");
    mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        MlsMessageOrAck::MlsMessage(external_commit_output.external_commit),
    )?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after diane joined externally): {members_str:?}");

    // Charlie receives Diana's application message
    let ptx = mls_platform_api::mls_receive(
        &state_global,
        &charlie_id,
        MlsMessageOrAck::MlsMessage(ctx),
    )?;

    println!(
        "\nCharlie receives Diana's message {:?}",
        String::from_utf8(ptx).unwrap()
    );

    //
    // Bob proposes to remove itself
    //
    println!("\nBob proposes a self remove");
    let self_remove_proposal = mls_group_propose_remove(&state_global, &gid, &bob_id, &bob_id)?;

    //
    // Diana receives the proposal from Bob
    //
    println!("\nDiana commits to the remove");
    let commit_5_output_bytes = mls_platform_api::mls_receive(
        &state_global,
        &diana_id,
        MlsMessageOrAck::MlsMessage(self_remove_proposal),
    )?;

    let commit_5_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_5_output_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_5_msg = MlsMessageOrAck::MlsMessage(commit_5_output.commit);

    // Diana processes the remove commit
    println!("\nDiana processes the remove commit");
    mls_platform_api::mls_receive(&state_global, &diana_id, commit_5_msg.clone())?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &diana_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (diana, after removing bob): {members_str:?}");

    // Charlie processes the remove commit
    println!("\nCharlie processes the remove commit");
    mls_platform_api::mls_receive(&state_global, &charlie_id, commit_5_msg.clone())?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after removing bob): {members_str:?}");

    // Bob processes the remove commit
    println!("\nBob processes the remove commit");
    let out_commit_5_bob = mls_platform_api::mls_receive(&state_global, &bob_id, commit_5_msg)?;
    let out_commit_5_bob_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&out_commit_5_bob)?;

    println!("Bob, out_commit_5 {out_commit_5_bob_str:?}");
    println!("Bob's state for the group has been removed");

    // Note: Bob cannot look at its own group state because it was already removed
    // let members = mls_platform_api::mls_group_members(&state_global, &gid, &bob_id)?;
    // let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    // println!("Members (bob, after its removal): {members_str:?}");

    //
    // Charlie decides that it's enough and closes the group
    //
    println!("\nCharlie decides that it's enough and closes the group");
    let commit_output_6_bytes =
        mls_platform_api::mls_group_close(&state_global, &gid, &charlie_id)?;

    let commit_6_output: mls_platform_api::MlsCommitOutput =
        from_slice(&commit_output_6_bytes).expect("Failed to deserialize MlsCommitOutput");

    let commit_6_msg = MlsMessageOrAck::MlsMessage(commit_6_output.commit);

    // Diana processes the close commit
    println!("\nDiana processes the close commit");
    let out_commit_6_diana =
        mls_platform_api::mls_receive(&state_global, &diana_id, commit_6_msg.clone())?;
    let out_commit_6_diana_str =
        mls_platform_api::utils_json_bytes_to_string_custom(&out_commit_6_diana)?;

    println!("Diana, out_commit_6 {out_commit_6_diana_str:?}");
    println!("Diana's state for the group has been removed");
    // Note: Diana cannot look at its own group state because it was already removed

    // Charlie processes the close commit
    println!("\nCharlie processes the close commit");
    mls_platform_api::mls_receive(&state_global, &charlie_id, commit_6_msg)?;

    let members = mls_platform_api::mls_group_members(&state_global, &gid, &charlie_id)?;
    let members_str = mls_platform_api::utils_json_bytes_to_string_custom(&members)?;
    println!("Members (charlie, after processing their group_close commit): {members_str:?}");

    // Charlie deletes her state for the group
    println!("\nCharlie deletes her state");
    let out = mls_platform_api::state_delete_group(&state_global, &gid, &charlie_id)?;
    let out_str = mls_platform_api::utils_json_bytes_to_string_custom(&out)?;

    println!("Charlie, group deletion confirmation {out_str:?}");

    Ok(())
}
