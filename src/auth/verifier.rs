use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{ApiKeyRecord, SecretVerifier};
use crate::config::SecretString;

type HmacSha256 = Hmac<Sha256>;

/// Bumped whenever derivation changes. Older versions remain verifiable so a
/// pepper or algorithm change is a migration, not an outage.
pub(crate) const VERIFIER_VERSION: u8 = 2;

#[derive(Clone)]
pub(crate) struct KeyVerifier {
    pepper: SecretString,
}

impl KeyVerifier {
    pub(crate) fn new(pepper: SecretString) -> Self {
        Self { pepper }
    }

    /// Derives the verifier stored for a newly issued key.
    pub(crate) fn verifier_for(&self, secret: &str) -> SecretVerifier {
        SecretVerifier(
            self.derive(secret, VERIFIER_VERSION)
                .expect("current verifier version is supported"),
        )
    }

    /// Constant-time comparison against the stored verifier.
    pub(crate) fn matches(&self, record: &ApiKeyRecord, secret: &str) -> bool {
        let Some(candidate) = self.derive(secret, record.verifier_version) else {
            return false;
        };

        bool::from(candidate.ct_eq(&record.verifier.0))
    }

    fn derive(&self, secret: &str, version: u8) -> Option<[u8; 32]> {
        match version {
            1 => Some(sha256(secret.as_bytes())),
            2 => Some(hmac_sha256(
                self.pepper.expose().as_bytes(),
                secret.as_bytes(),
            )),
            _ => None,
        }
    }
}

fn sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length; this cannot fail.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::auth::{ApiKeyId, ClientId};

    fn record(verifier: SecretVerifier, version: u8) -> ApiKeyRecord {
        ApiKeyRecord {
            key_id: ApiKeyId("key".to_owned()),
            client_id: ClientId("client".to_owned()),
            verifier,
            verifier_version: version,
            scopes: HashSet::new(),
            expires_at: None,
            revoked_at: None,
        }
    }

    fn verifier(pepper: &str) -> KeyVerifier {
        KeyVerifier::new(SecretString::new(pepper))
    }

    #[test]
    fn accepts_the_issued_secret() {
        let verifier = verifier("pepper");
        let stored = verifier.verifier_for("correct-horse");

        assert!(verifier.matches(&record(stored, VERIFIER_VERSION), "correct-horse"));
        assert!(!verifier.matches(
            &record(verifier.verifier_for("correct-horse"), VERIFIER_VERSION),
            "wrong"
        ));
    }

    #[test]
    fn pepper_is_part_of_the_secret_derivation() {
        let stored = verifier("pepper-a").verifier_for("same-secret");

        assert!(!verifier("pepper-b").matches(&record(stored, VERIFIER_VERSION), "same-secret"));
    }

    #[test]
    fn verifies_legacy_version_one_hashes() {
        let legacy = SecretVerifier(sha256(b"legacy-secret"));

        assert!(verifier("any-pepper").matches(&record(legacy, 1), "legacy-secret"));
    }

    #[test]
    fn rejects_unknown_verifier_versions() {
        let stored = verifier("pepper").verifier_for("secret");

        assert!(!verifier("pepper").matches(&record(stored, 9), "secret"));
    }

    #[test]
    fn derivation_is_stable() {
        let verifier = verifier("pepper");

        assert_eq!(
            verifier.verifier_for("secret").0,
            verifier.verifier_for("secret").0
        );
        assert_ne!(
            verifier.verifier_for("secret").0,
            verifier.verifier_for("other").0
        );
    }
}
