use unicode_normalization::UnicodeNormalization;

use crate::{Result, err};

/// Prefix shared by the bcrypt variants ($2a$, $2b$, $2x$, $2y$).
const PREFIX: &str = "$2";

pub(super) fn is_hash(password_hash: &str) -> bool { password_hash.starts_with(PREFIX) }

/// Verifies against a hash written by Synapse, which NFKC-normalizes the
/// password before handing it to bcrypt.
pub(super) fn verify_password(password: &str, password_hash: &str) -> Result {
	let password: String = password.nfkc().collect();
	::bcrypt::verify(password, password_hash)
		.map_err(|e| err!("{e}"))?
		.then_some(())
		.ok_or_else(|| err!("unverified"))
}

#[cfg(test)]
mod tests {
	use crate::utils::hash;

	// Produced by Synapse (python bcrypt, 12 rounds) for "temp123".
	const SYNAPSE_HASH: &str = "$2b$12$SBCex8KQ5tjrIm7U4Vt6h.eNf7cF3/GJTcC/oaRH9/VrLnK5RQWJ6";

	// Produced by Synapse for "ｐａｓｓ①", which NFKC-normalizes to "pass1".
	const SYNAPSE_NFKC_HASH: &str =
		"$2b$04$.5Y4bjQDdugzQ7v91bZ6fuBDlf8Q64SeINcnGjqoFNT.KmHQ6t.k6";

	#[test]
	fn synapse_hash_verify() {
		hash::verify_password("temp123", SYNAPSE_HASH).expect("verified");
	}

	#[test]
	fn synapse_hash_verify_nfkc() {
		hash::verify_password("ｐａｓｓ①", SYNAPSE_NFKC_HASH).expect("verified");
		hash::verify_password("pass1", SYNAPSE_NFKC_HASH).expect("verified");
	}

	#[test]
	#[should_panic(expected = "unverified")]
	fn synapse_hash_verify_fail() {
		hash::verify_password("temp321", SYNAPSE_HASH).expect("unverified");
	}

	#[test]
	fn synapse_hash_is_legacy() {
		assert!(hash::is_legacy_password_hash(SYNAPSE_HASH));
		let argon = hash::password("temp123").expect("digest");
		assert!(!hash::is_legacy_password_hash(&argon));
	}
}
