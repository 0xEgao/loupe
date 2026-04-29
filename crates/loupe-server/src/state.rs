use std::sync::Arc;

use loupe_storage::Db;

/// Shared state passed to every axum handler. Cheap to clone — wraps an
/// `Arc` around the storage handle.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
}

impl AppState {
	pub fn new(db: Arc<Db>) -> Self {
		Self { db }
	}
}
