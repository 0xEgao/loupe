use loupe_core::{JobKind, JobState};
use serde::{Deserialize, Serialize};

/// Body of `POST /v1/repos/:id/scan` (admin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
	pub protocol_version: u16,
	#[serde(default)]
	pub incremental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResponse {
	pub protocol_version: u16,
	pub job_id: i64,
}

/// Listing entry for `GET /v1/jobs` and `GET /v1/jobs/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInfo {
	pub job_id: i64,
	pub repo_id: i64,
	pub kind: JobKind,
	pub state: JobState,
	pub incremental: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub since_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub head_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub parent_job_id: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub target_finding_id: Option<i64>,
	pub attempts: u32,
	pub enqueued_at: i64,
}

#[cfg(test)]
mod tests {
	use loupe_core::{JobKind, JobState};

	use super::*;

	#[test]
	fn scan_request_defaults_incremental_false() {
		let req: ScanRequest = serde_json::from_str(r#"{"protocol_version":1}"#).unwrap();
		assert!(!req.incremental);
	}

	#[test]
	fn job_info_round_trips() {
		let info = JobInfo {
			job_id: 1,
			repo_id: 2,
			kind: JobKind::Scan,
			state: JobState::Queued,
			incremental: false,
			since_sha: None,
			head_sha: None,
			parent_job_id: None,
			target_finding_id: None,
			attempts: 0,
			enqueued_at: 1_700_000_000,
		};
		let s = serde_json::to_string(&info).unwrap();
		let back: JobInfo = serde_json::from_str(&s).unwrap();
		assert_eq!(info, back);
	}

	#[test]
	fn verify_job_carries_parentage() {
		let info = JobInfo {
			job_id: 5,
			repo_id: 2,
			kind: JobKind::Verify,
			state: JobState::Leased,
			incremental: false,
			since_sha: None,
			head_sha: Some("abc123".into()),
			parent_job_id: Some(1),
			target_finding_id: Some(42),
			attempts: 0,
			enqueued_at: 1_700_000_100,
		};
		let s = serde_json::to_string(&info).unwrap();
		let back: JobInfo = serde_json::from_str(&s).unwrap();
		assert_eq!(info, back);
	}
}
