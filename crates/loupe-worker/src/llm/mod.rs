//! LLM backend abstraction.
//!
//! A `LlmBackend` is one provider of agentic completions: it receives a
//! prompt and a read-only working directory, manages its own internal
//! tool loop (the `claude` CLI does this for us; an HTTP backend would
//! manage one explicitly), and returns the model's final text response.
//!
//! The first concrete impl is [`ClaudeCliBackend`] which shells out to
//! the `claude` CLI. Future impls (Codex CLI, direct Anthropic API)
//! plug in without touching scanner code.

pub mod claude_cli;
pub mod prompts;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
pub use claude_cli::ClaudeCliBackend;
use tokio_util::sync::CancellationToken;

/// Default per-call wall-clock budget. Per-file LLM invocations should
/// fit comfortably within this; if they don't, the call is aborted and
/// the file is treated as having produced no findings (logged warning).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Pull the first balanced JSON object out of a possibly noisy text
/// response. Tolerates prose before/after the object and a single
/// markdown fence around it. Returns the slice as an owned `String`
/// because the model occasionally emits trailing junk after the
/// closing brace; we feed only what's inside the braces.
///
/// Used by the verifier scanner, which still parses JSON from the
/// model's stdout. The discovery flow doesn't need this — submission
/// goes through the MCP `submit_finding` tool.
pub fn extract_json_object(text: &str) -> Option<String> {
	let bytes = text.as_bytes();
	let start = bytes.iter().position(|b| *b == b'{')?;
	let mut depth = 0i32;
	let mut in_str = false;
	let mut escape = false;
	for (i, b) in bytes.iter().enumerate().skip(start) {
		if in_str {
			if escape {
				escape = false;
			} else if *b == b'\\' {
				escape = true;
			} else if *b == b'"' {
				in_str = false;
			}
			continue;
		}
		match *b {
			b'"' => in_str = true,
			b'{' => depth += 1,
			b'}' => {
				depth -= 1;
				if depth == 0 {
					return std::str::from_utf8(&bytes[start..=i]).ok().map(|s| s.to_owned());
				}
			},
			_ => {},
		}
	}
	None
}

#[derive(Debug, Clone)]
pub struct LlmRequest {
	pub prompt: String,
	/// Read-only working directory the backend may inspect (e.g. the
	/// scanned worktree).
	pub workdir: PathBuf,
	pub timeout: Duration,
	pub cancel: CancellationToken,
	/// Repo id for the scan currently in progress. When `Some`, the
	/// backend may attach the loupe MCP server to its agent
	/// invocation so the model can call tools like
	/// `query_prior_findings` scoped to this repo. `None` falls back
	/// to the no-MCP behaviour (just prompt + stdout).
	pub repo_id: Option<i64>,
	/// Job id for the scan currently in progress. Required for the
	/// `submit_finding` MCP tool to POST to
	/// `/v1/jobs/{job_id}/findings`; without it, that tool is not
	/// advertised. `None` falls back to query-only MCP usage (the
	/// agent can read prior findings but can't write new ones).
	pub job_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
	pub text: String,
	pub backend_id: &'static str,
}

#[async_trait::async_trait]
pub trait LlmBackend: Send + Sync {
	/// Stable identifier — appears in logs and in `Finding.scanner_id`
	/// when the backend is the source of truth for a finding.
	fn id(&self) -> &'static str;

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse>;
}

pub mod testing {
	//! Stub backend for testing scanners without invoking a real LLM
	//! CLI / API. Tests pass a closure that produces canned responses
	//! based on the request's prompt or workdir.
	//!
	//! Lives outside `#[cfg(test)]` so integration tests in sibling
	//! crates (e.g. `loupe-server/tests/llm_dispatch.rs`) can reach it.
	//! Not intended for production wiring.
	//!
	//! Two constructors:
	//! - [`StubLlmBackend::new`] takes a sync closure — simplest for
	//!   unit tests that just need a canned text response.
	//! - [`StubLlmBackend::new_async`] takes an async closure — needed
	//!   for integration tests that simulate the agent's MCP
	//!   `submit_finding` tool by POSTing to a real loupe-server
	//!   inside the closure. The agent's tool calls happen during the
	//!   session in production; the async stub gives tests the same
	//!   "while the LLM is running" hook.

	use std::future::Future;
	use std::pin::Pin;
	use std::sync::Arc;

	use anyhow::Result;
	use async_trait::async_trait;

	use super::{LlmBackend, LlmRequest, LlmResponse};

	type AsyncStubFn = Arc<
		dyn Fn(LlmRequest) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send + Sync,
	>;

	pub struct StubLlmBackend {
		id: &'static str,
		f: AsyncStubFn,
	}

	impl StubLlmBackend {
		/// Create a stub whose closure is sync — good for unit tests
		/// that don't need to call back into anything async.
		pub fn new<F>(id: &'static str, f: F) -> Self
		where
			F: Fn(&LlmRequest) -> Result<String> + Send + Sync + 'static,
		{
			let f = Arc::new(f);
			Self {
				id,
				f: Arc::new(move |req: LlmRequest| {
					let f = f.clone();
					Box::pin(async move { f(&req) })
				}),
			}
		}

		/// Create a stub whose closure can `.await` — used by tests
		/// that simulate the agent calling `submit_finding` mid-
		/// session against a real server fixture.
		pub fn new_async<F, Fut>(id: &'static str, f: F) -> Self
		where
			F: Fn(LlmRequest) -> Fut + Send + Sync + 'static,
			Fut: Future<Output = Result<String>> + Send + 'static,
		{
			Self { id, f: Arc::new(move |req| Box::pin(f(req))) }
		}
	}

	#[async_trait]
	impl LlmBackend for StubLlmBackend {
		fn id(&self) -> &'static str {
			self.id
		}

		async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
			let text = (self.f)(req).await?;
			Ok(LlmResponse { text, backend_id: self.id })
		}
	}
}
