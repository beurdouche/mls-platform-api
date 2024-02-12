// Stateless function
pub fn mls_stateless_generate_signature_keypair(
    name: &str,
    cs: CipherSuite,
    _randomness: Option<Vec<u8>>,
) -> Result<(SigningIdentity, SignatureSecretKey), MlsError> {
    let crypto_provider = DefaultCryptoProvider::default();
    let cipher_suite = crypto_provider.cipher_suite_provider(cs).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    // Create the credential and the signing identity.
    // TODO: Handle X.509 certificates
    let credential = generate_credential(name)?;
    let signing_identity: SigningIdentity =
        SigningIdentity::new(credential.into_credential(), public);

    Ok((signing_identity, secret))
}

// TODO: Look into capabilities that might be missing here...
pub fn mls_stateless_generate_key_package(
    group_config: Option<GroupConfig>,
    myself: SigningIdentity,
    myself_sigkey: SignatureSecretKey,
    _randomness: Option<Vec<u8>>,
) -> Result<(MlsMessage, KeyPackageData), MlsError> {
    let mut state = TemporaryState::new();

    state.insert_sigkey(
        &myself,
        &myself_sigkey,
        // TODO make default config if None
        group_config.clone().unwrap().ciphersuite,
    );

    let client = state.client(myself, group_config)?;
    let key_package = client.generate_key_package_message()?;

    let mut state = state.key_packages.lock().unwrap();
    let key = state.keys().next().unwrap().clone();

    let key_package_data = state.remove(&key).unwrap();

    Ok((key_package, key_package_data.key_package_data))
}
