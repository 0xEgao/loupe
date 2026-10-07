//! DAO for the server-wide GitHub App credential.
//!
//! One loupe-server deployment reports through at most one GitHub App,
//! so the credential lives in a single `secrets` row (`kind =
//! "github_app"`, `label = "server"`) rather than in a table of its own.
//! The value is a JSON blob holding the app id, its slug (for display),
//! and the private key PEM; SQLCipher seals the whole file, so the PEM
//! is stored as-is like a PAT would be.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::secrets::SecretKind;

const LABEL: &str = "server";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGithubApp {
	pub app_id: u64,
	pub slug: String,
	pub private_key_pem: String,
}

/// Store (or replace) the credential.
pub fn set(conn: &Connection, app: &StoredGithubApp, now: i64) -> rusqlite::Result<()> {
	let value = serde_json::to_vec(app)
		.map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
	conn.execute(
		"INSERT INTO secrets (kind, label, value, created_at)
		 VALUES (?1, ?2, ?3, ?4)
		 ON CONFLICT(kind, label) DO UPDATE SET value = excluded.value,
		                                       created_at = excluded.created_at",
		params![SecretKind::GithubApp.as_str(), LABEL, value, now],
	)?;
	Ok(())
}

/// Read the credential. `Ok(None)` when no app has been configured.
pub fn get(conn: &Connection) -> rusqlite::Result<Option<StoredGithubApp>> {
	let bytes: Option<Vec<u8>> = conn
		.query_row(
			"SELECT value FROM secrets WHERE kind = ?1 AND label = ?2",
			params![SecretKind::GithubApp.as_str(), LABEL],
			|r| r.get(0),
		)
		.optional()?;
	bytes
		.map(|b| {
			serde_json::from_slice(&b).map_err(|e| {
				rusqlite::Error::FromSqlConversionFailure(
					0,
					rusqlite::types::Type::Blob,
					Box::new(e),
				)
			})
		})
		.transpose()
}

/// Remove the credential. Returns whether one was stored.
pub fn clear(conn: &Connection) -> rusqlite::Result<bool> {
	let n = conn.execute(
		"DELETE FROM secrets WHERE kind = ?1 AND label = ?2",
		params![SecretKind::GithubApp.as_str(), LABEL],
	)?;
	Ok(n > 0)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secrets::MasterKey;
	use crate::Db;

	fn app(app_id: u64) -> StoredGithubApp {
		StoredGithubApp {
			app_id,
			slug: format!("loupe-{app_id}"),
			private_key_pem: "-----BEGIN RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY-----\n"
				.into(),
		}
	}

	#[test]
	fn get_is_none_until_set() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		assert_eq!(db.with_conn(|c| Ok(get(c)?)).unwrap(), None);
	}

	#[test]
	fn round_trips_and_overwrites() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		db.with_conn(|c| Ok(set(c, &app(1), 10)?)).unwrap();
		assert_eq!(db.with_conn(|c| Ok(get(c)?)).unwrap(), Some(app(1)));
		db.with_conn(|c| Ok(set(c, &app(2), 20)?)).unwrap();
		assert_eq!(db.with_conn(|c| Ok(get(c)?)).unwrap(), Some(app(2)));
		let rows: i64 = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT COUNT(*) FROM secrets WHERE kind = 'github_app'",
					[],
					|r| r.get(0),
				)?)
			})
			.unwrap();
		assert_eq!(rows, 1, "set must replace, not accumulate");
	}

	#[test]
	fn clear_reports_whether_anything_was_stored() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		assert!(!db.with_conn(|c| Ok(clear(c)?)).unwrap());
		db.with_conn(|c| Ok(set(c, &app(1), 10)?)).unwrap();
		assert!(db.with_conn(|c| Ok(clear(c)?)).unwrap());
		assert_eq!(db.with_conn(|c| Ok(get(c)?)).unwrap(), None);
	}
}
