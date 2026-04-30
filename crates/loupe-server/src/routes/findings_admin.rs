//! Admin-only findings inspection + approval routes:
//!
//! - `GET  /v1/repos/:id/findings` → recent findings for a repo
//! - `GET  /v1/findings/:id`       → full detail for one finding
//! - `POST /v1/findings/:id/approve` → release a held finding
//! - `POST /v1/findings/:id/reject`  → terminally dismiss a held finding

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use loupe_proto::{FindingDetail, FindingSummary, ListFindingsResponse, PROTOCOL_VERSION};
use loupe_storage::findings::{self, ApprovalOutcome, FindingRow};

use crate::auth::AuthedWorker;
use crate::state::AppState;

/// How many findings the listing endpoint returns by default. Operators
/// who need to page further should narrow by repo and follow up via
/// `loupectl finding get <id>` for individual rows.
const LIST_LIMIT: i64 = 100;

pub async fn list_for_repo(
	State(state): State<AppState>, Path(repo_id): Path<i64>,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	let rows = state
		.db
		.with_conn(|c| Ok(findings::list_for_repo(c, repo_id, LIST_LIMIT)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing findings: {e}")))?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

pub async fn get(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<Json<FindingDetail>, (StatusCode, String)> {
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get finding: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;
	Ok(Json(row_to_detail(row)))
}

/// `POST /v1/findings/:id/approve` — admin only. Transitions a
/// finding sitting in `awaiting_approval` into `confirmed` and runs
/// the dispatcher, so the operator's click immediately fires the
/// reporter. Stamps `approved_at` + `approved_by_cn` (the admin
/// client cert's worker.name). 404 if the finding doesn't exist;
/// 409 if the finding exists but isn't in `awaiting_approval` (e.g.
/// already approved, already dispatched, or never gated).
pub async fn approve(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let cn = authed.worker.name.clone();
	let outcome = state
		.db
		.with_conn(|c| Ok(findings::approve(c, id, &cn, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("approve finding: {e}")))?;
	match outcome {
		ApprovalOutcome::Applied => {
			if let Err(e) = super::jobs::dispatch_finding(&state, id, now).await {
				tracing::warn!(finding_id = id, error = %e, "dispatch on approve failed");
			}
			Ok(StatusCode::NO_CONTENT)
		},
		ApprovalOutcome::NotPending => {
			Err((StatusCode::CONFLICT, format!("finding {id} is not awaiting approval")))
		},
		ApprovalOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no finding with id {id}")))
		},
	}
}

/// `POST /v1/findings/:id/reject` — admin only. Transitions a held
/// finding into terminal `dismissed` with `rejected_at` +
/// `rejected_by_cn` stamped. Distinct from a verifier-issued
/// `dismiss` (which leaves `rejected_*` NULL), so dashboards can
/// tell the two apart later.
pub async fn reject(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let cn = authed.worker.name.clone();
	let outcome = state
		.db
		.with_conn(|c| Ok(findings::reject(c, id, &cn, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("reject finding: {e}")))?;
	match outcome {
		ApprovalOutcome::Applied => Ok(StatusCode::NO_CONTENT),
		ApprovalOutcome::NotPending => {
			Err((StatusCode::CONFLICT, format!("finding {id} is not awaiting approval")))
		},
		ApprovalOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no finding with id {id}")))
		},
	}
}

fn row_to_summary(r: FindingRow) -> FindingSummary {
	FindingSummary {
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		file_path: r.file_path,
		line_start: r.line_start,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
		approved_at: r.approved_at,
		approved_by_cn: r.approved_by_cn,
		rejected_at: r.rejected_at,
		rejected_by_cn: r.rejected_by_cn,
	}
}

fn row_to_detail(r: FindingRow) -> FindingDetail {
	FindingDetail {
		protocol_version: PROTOCOL_VERSION,
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		description: r.description,
		file_path: r.file_path,
		line_start: r.line_start,
		line_end: r.line_end,
		cwe: r.cwe,
		patch_unified: r.patch_unified,
		poc_unified: r.poc_unified,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
		approved_at: r.approved_at,
		approved_by_cn: r.approved_by_cn,
		rejected_at: r.rejected_at,
		rejected_by_cn: r.rejected_by_cn,
	}
}
