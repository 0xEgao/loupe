use loupe_core::ReportingDestination;
use serde::{Deserialize, Serialize};

use crate::version::PROTOCOL_VERSION;

/// Body of `POST /v1/repos`. The `pat_secret_id` referenced inside
/// `reporting` must already exist in the server's `secrets` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRepoRequest {
	pub protocol_version: u16,
	pub clone_url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<u64>,
	pub reporting: ReportingDestination,
	#[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
	pub scanner_config: serde_json::Value,
}

impl RegisterRepoRequest {
	pub fn new(clone_url: impl Into<String>, reporting: ReportingDestination) -> Self {
		Self {
			protocol_version: PROTOCOL_VERSION,
			clone_url: clone_url.into(),
			branch: None,
			scan_interval_seconds: None,
			reporting,
			scanner_config: serde_json::Value::Null,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRepoResponse {
	pub protocol_version: u16,
	pub repo_id: i64,
}

/// Body of `POST /v1/workers` (admin-only). Returns the freshly-minted
/// client cert + key + the CA cert; this is the **only** time the client
/// key leaves the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
	pub protocol_version: u16,
	pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerResponse {
	pub protocol_version: u16,
	pub worker_id: i64,
	pub client_cert_pem: String,
	pub client_key_pem: String,
	pub ca_cert_pem: String,
}

#[cfg(test)]
mod tests {
	use loupe_core::ReportingDestination;
	use serde_json::json;

	use super::*;

	#[test]
	fn register_repo_request_round_trips() {
		let req = RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/acme/widget.git".into(),
			branch: Some("main".into()),
			scan_interval_seconds: Some(3600),
			reporting: ReportingDestination::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "security".into(),
				pat_secret_id: 1,
			},
			scanner_config: json!({"regex": {"enabled": true}}),
		};
		let s = serde_json::to_string(&req).unwrap();
		let back: RegisterRepoRequest = serde_json::from_str(&s).unwrap();
		assert_eq!(req, back);
	}

	#[test]
	fn register_worker_response_carries_pem_triple() {
		let resp = RegisterWorkerResponse {
			protocol_version: PROTOCOL_VERSION,
			worker_id: 17,
			client_cert_pem: "-----BEGIN CERTIFICATE-----\n...".into(),
			client_key_pem: "-----BEGIN PRIVATE KEY-----\n...".into(),
			ca_cert_pem: "-----BEGIN CERTIFICATE-----\n...".into(),
		};
		let s = serde_json::to_string(&resp).unwrap();
		let back: RegisterWorkerResponse = serde_json::from_str(&s).unwrap();
		assert_eq!(resp, back);
	}
}
