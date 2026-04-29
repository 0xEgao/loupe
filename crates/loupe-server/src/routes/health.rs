use axum::http::StatusCode;
use axum::Json;
use loupe_proto::PROTOCOL_VERSION;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
	pub status: &'static str,
	pub protocol_version: u16,
}

/// `GET /v1/health` — no auth, no DB hit. Liveness only.
pub async fn get() -> (StatusCode, Json<HealthResponse>) {
	(StatusCode::OK, Json(HealthResponse { status: "ok", protocol_version: PROTOCOL_VERSION }))
}
