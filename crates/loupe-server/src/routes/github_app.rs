//! Admin-only management of the server-wide GitHub App credential.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use loupe_proto::{GithubAppResponse, GithubAppSummary, SetGithubAppRequest, PROTOCOL_VERSION};
use loupe_storage::github_app::{self, StoredGithubApp};

use crate::reporters::github_app::GithubAppKey;
use crate::state::AppState;

/// `PUT /v1/github-app` — admin only. Parses the private key, proves it
/// against GitHub's `GET /app`, checks the app id matches, and stores
/// the credential. Replaces any previously stored app.
pub async fn set(
	State(state): State<AppState>, Json(req): Json<SetGithubAppRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.app_id == 0 {
		return Err((StatusCode::BAD_REQUEST, "app_id must be positive".into()));
	}
	let key = GithubAppKey::from_pem(req.app_id, &req.private_key_pem)
		.map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid GitHub App private key: {e:#}")))?;
	let info = state.github_reporter.verify_app(&key).await.map_err(|e| {
		(StatusCode::BAD_REQUEST, format!("GitHub rejected the app credential: {e:#}"))
	})?;
	if info.id != req.app_id {
		return Err((
			StatusCode::BAD_REQUEST,
			format!(
				"private key belongs to GitHub App {} ({}), not {}",
				info.id, info.slug, req.app_id
			),
		));
	}

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let stored = StoredGithubApp {
		app_id: req.app_id,
		slug: info.slug,
		private_key_pem: req.private_key_pem,
	};
	state
		.db
		.with_conn(|c| Ok(github_app::set(c, &stored, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("storing GitHub App: {e}")))?;
	Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/github-app` — admin only. Reports which app is configured
/// without ever returning the key.
pub async fn get(
	State(state): State<AppState>,
) -> Result<Json<GithubAppResponse>, (StatusCode, String)> {
	let stored = state
		.db
		.with_conn(|c| Ok(github_app::get(c)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("reading GitHub App: {e}")))?;
	Ok(Json(GithubAppResponse {
		protocol_version: PROTOCOL_VERSION,
		app: stored.map(|app| GithubAppSummary { app_id: app.app_id, slug: app.slug }),
	}))
}

/// `DELETE /v1/github-app` — admin only. Removes the stored credential.
pub async fn clear(State(state): State<AppState>) -> Result<StatusCode, (StatusCode, String)> {
	let removed = state
		.db
		.with_conn(|c| Ok(github_app::clear(c)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("clearing GitHub App: {e}")))?;
	if removed {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, "no GitHub App configured".into()))
	}
}
