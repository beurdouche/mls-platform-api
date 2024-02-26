///
/// Helper functions for SigningIdentity
///
fn serialize_signing_identity(
    signing_identity: &SigningIdentity,
) -> Result<Vec<u8>, mls_rs::mls_rs_codec::Error> {
    signing_identity.mls_encode_to_vec()
}

fn deserialize_signing_identity(
    bytes: &[u8],
) -> Result<SigningIdentity, mls_rs::mls_rs_codec::Error> {
    SigningIdentity::mls_decode(&mut &*bytes)
}
