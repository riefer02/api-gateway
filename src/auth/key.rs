use std::collections::HashSet;

use time::OffsetDateTime;

use super::store::NewApiKey;
use super::verifier::VERIFIER_VERSION;
use super::{ApiKeyId, ClientId, KeyVerifier};

const KEY_ID_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;

/// Generates a key id and a high-entropy secret, returning the write model
/// and the plaintext secret. The secret is shown exactly once.
pub(crate) fn generate(
    verifier: &KeyVerifier,
    client_id: ClientId,
    scopes: HashSet<String>,
    expires_at: Option<OffsetDateTime>,
) -> Result<(NewApiKey, String), getrandom::Error> {
    let mut id_bytes = [0_u8; KEY_ID_BYTES];
    getrandom::fill(&mut id_bytes)?;

    let mut secret_bytes = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut secret_bytes)?;

    let key_id = ApiKeyId(hex::encode(id_bytes));
    let secret = hex::encode(secret_bytes);

    let key = NewApiKey {
        key_id,
        client_id,
        verifier: verifier.verifier_for(&secret),
        verifier_version: VERIFIER_VERSION,
        scopes,
        expires_at,
    };

    Ok((key, secret))
}

/// Wire format: `<key_id>.<secret>`. The id is public, the secret is not.
pub(crate) fn token(key_id: &ApiKeyId, secret: &str) -> String {
    format!("{key_id}.{secret}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretString;

    fn verifier() -> KeyVerifier {
        KeyVerifier::new(SecretString::new("test-pepper"))
    }

    #[test]
    fn generates_distinct_keys() {
        let (first, first_secret) = generate(
            &verifier(),
            ClientId("client".to_owned()),
            HashSet::from(["read".to_owned()]),
            None,
        )
        .expect("generate");

        let (second, second_secret) = generate(
            &verifier(),
            ClientId("client".to_owned()),
            HashSet::from(["read".to_owned()]),
            None,
        )
        .expect("generate");

        assert_ne!(first.key_id, second.key_id);
        assert_ne!(first_secret, second_secret);
        assert_eq!(first_secret.len(), SECRET_BYTES * 2);
        assert_eq!(first.key_id.0.len(), KEY_ID_BYTES * 2);
    }

    #[test]
    fn token_round_trips_through_the_wire_format() {
        let (key, secret) = generate(
            &verifier(),
            ClientId("client".to_owned()),
            HashSet::new(),
            None,
        )
        .expect("generate");

        let token = token(&key.key_id, &secret);
        let (key_id, parsed_secret) = token
            .split_once('.')
            .expect("wire format");

        assert_eq!(key_id, key.key_id.as_str());
        assert_eq!(parsed_secret, secret);
    }
}
