use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use thiserror::Error;

use crate::migrations::{apply_pending, current_schema_version};

#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Owning handle to the SQLite database. We use a single `Mutex<Connection>`
/// rather than a connection pool — the bkb-ingest experience is that
/// rusqlite's WAL-mode single-writer model copes fine with our query
/// volume, and a pool adds dependencies (`r2d2_sqlite`) we'd rather not
/// pay for. Swap in Postgres at the seam if multi-instance deployment
/// becomes necessary.
pub struct Db {
	conn: Mutex<Connection>,
}

impl Db {
	/// Open (or create) a database at `path`, running migrations to the
	/// current schema version. WAL mode is enabled so reads don't block
	/// writes.
	pub fn open(path: impl AsRef<Path>) -> Result<Self> {
		let conn = Connection::open(path)?;
		Self::bootstrap(conn)
	}

	/// In-memory database. Useful in tests and for the `--ephemeral` mode
	/// of the server.
	pub fn open_in_memory() -> Result<Self> {
		let conn = Connection::open_in_memory()?;
		Self::bootstrap(conn)
	}

	fn bootstrap(mut conn: Connection) -> Result<Self> {
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		conn.pragma_update(None, "synchronous", "NORMAL")?;
		apply_pending(&mut conn)?;
		Ok(Self { conn: Mutex::new(conn) })
	}

	/// Run a closure with exclusive access to the underlying connection.
	pub fn with_conn<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
		let mut guard = self.conn.lock().expect("loupe-storage db mutex poisoned");
		f(&mut guard)
	}

	/// Highest applied migration version.
	pub fn schema_version(&self) -> Result<u32> {
		self.with_conn(|c| Ok(current_schema_version(c)?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::migrations::LATEST_SCHEMA_VERSION;

	#[test]
	fn fresh_in_memory_db_is_at_latest_version() {
		let db = Db::open_in_memory().unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn reopening_does_not_re_apply_migrations() {
		// Reopening a memory db isn't possible, so simulate by running
		// `apply_pending` twice on the same connection.
		let db = Db::open_in_memory().unwrap();
		db.with_conn(|c| {
			crate::migrations::apply_pending(c)?;
			crate::migrations::apply_pending(c)?;
			Ok(())
		})
		.unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}
}
