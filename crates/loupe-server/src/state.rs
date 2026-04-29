use std::sync::Arc;

use loupe_storage::Db;
use loupe_tls::Ca;
use tokio::sync::Notify;

use crate::reporters::GithubReporter;

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage, the internal CA, and the reporter that the
/// dispatcher hands findings to.
///
/// `job_arrived` is poked whenever a new job lands in `queued`. Long-
/// polling lease handlers wait on it so workers don't have to busy-poll.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
	pub github_reporter: Arc<GithubReporter>,
	pub job_arrived: Arc<Notify>,
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>, github_reporter: Arc<GithubReporter>) -> Self {
		Self { db, ca, github_reporter, job_arrived: Arc::new(Notify::new()) }
	}
}
