//! Password hashing and cryptographic digest utilities.
//!
//! Password helpers use Argon2id with a fresh random salt for each new hash.
//! Bcrypt hashes imported from Synapse are accepted for verification only.
//! The SHA-256 submodule provides byte-oriented digest helpers.

mod argon;
mod bcrypt;

pub mod sha256;

use crate::Result;

/// Verifies a plaintext password against an encoded Argon2 or bcrypt password
/// hash.
///
/// Malformed hashes and password mismatches return an error. Success is
/// represented by `Ok(())`.
pub fn verify_password(password: &str, password_hash: &str) -> Result {
	if bcrypt::is_hash(password_hash) {
		return bcrypt::verify_password(password, password_hash);
	}

	argon::verify_password(password, password_hash)
}

/// Whether the hash is a non-Argon2 format that should be replaced by
/// [`password`] once the plaintext is known.
#[must_use]
pub fn is_legacy_password_hash(password_hash: &str) -> bool { bcrypt::is_hash(password_hash) }

/// Hashes a plaintext password with Argon2id.
///
/// A fresh random salt is generated for every call. The result is a
/// PHC-formatted string containing the salt and parameters needed for
/// verification.
pub fn password(password: &str) -> Result<String> { argon::password(password) }
