//! Backend that shells out to the `codex` CLI (OpenAI Codex).
//!
//! Mirrors [`ClaudeCliBackend`]'s shape: runs the agent inside the
//! bubblewrap sandbox the worker builds, forwards the model auth env
//! var (`OPENAI_API_KEY`), and bind-mounts the operator's `~/.codex/`
//! config dir so a `codex login`-style OAuth credential can flow in.
//!
//! Wire shape: `codex exec --dangerously-bypass-approvals-and-sandbox
//! --skip-git-repo-check "$prompt"`. The bypass flag is the codex
//! analog of claude's `--dangerously-skip-permissions`; the bwrap
//! sandbox is the actual security boundary, not codex's own
//! permission machinery.
//!
//! MCP integration is intentionally not wired for codex yet. The
//! current consumer (the verifier scanner) doesn't need MCP — the
//! original finding is rendered into the prompt and the model just
//! returns a JSON verdict — and codex's MCP-config surface (TOML
//! under `~/.codex/config.toml` / `--config mcp_servers...`) differs
//! from claude's `--mcp-config <file>` enough to deserve its own
//! pass.
//!
//! [`ClaudeCliBackend`]: super::ClaudeCliBackend

use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::{LlmBackend, LlmRequest, LlmResponse};
use crate::sandbox::SandboxBuilder;

const BACKEND_ID: &str = "codex-cli";
const CODEX_BIN: &str = "codex";

/// Cap a borrow at `n` chars; appends an ellipsis if the original was
/// longer. Used to keep error messages from blowing up when the CLI
/// dumps multi-MB diagnostics on a non-zero exit.
fn truncate(s: &str, n: usize) -> String {
	let mut buf: String = s.chars().take(n).collect();
	if s.chars().nth(n).is_some() {
		buf.push('…');
	}
	buf.replace('\n', " ")
}

pub struct CodexCliBackend {
	bin: String,
}

impl CodexCliBackend {
	pub fn new() -> Self {
		Self { bin: CODEX_BIN.to_owned() }
	}

	pub fn with_bin(bin: impl Into<String>) -> Self {
		Self { bin: bin.into() }
	}
}

impl Default for CodexCliBackend {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl LlmBackend for CodexCliBackend {
	fn id(&self) -> &'static str {
		BACKEND_ID
	}

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
		tracing::debug!(
			backend = BACKEND_ID,
			workdir = %req.workdir.display(),
			prompt_chars = req.prompt.chars().count(),
			timeout_ms = req.timeout.as_millis() as u64,
			"codex-cli: invoking",
		);
		let started = std::time::Instant::now();

		let mut sandbox = SandboxBuilder::new(&req.workdir)
			.allow_network()
			// Per-user installs (`npm i -g @openai/codex` with a non-root
			// prefix, etc.) live outside the default sandbox mounts —
			// surface the install tree so the wrapped subprocess can
			// `exec` it.
			.allow_binary(&self.bin)
			.with_context(|| format!("preparing sandbox for `{}`", self.bin))?
			.forward_env("OPENAI_API_KEY");
		if let Some(home) = std::env::var_os("HOME") {
			let host_home = std::path::PathBuf::from(home);
			let codex_dir = host_home.join(".codex");
			// Bind only the credential + config files read-only,
			// rather than the whole `~/.codex/` tree. Codex writes a
			// models cache and (sometimes) an installation_id to its
			// home dir on every invocation; binding the parent
			// read-only fails those writes with EROFS. Leaving the
			// parent as the sandbox tmpfs keeps `auth.json` /
			// `config.toml` reachable and the cache writable per call.
			//
			// `--ro-bind-try` (used inside SandboxBuilder) makes a
			// missing source a no-op — env-only auth (just
			// `OPENAI_API_KEY`) Just Works on hosts that never ran
			// `codex login`, and a missing `config.toml` is fine since
			// codex falls back to defaults.
			sandbox = sandbox
				.bind_ro(codex_dir.join("auth.json"), "/home/scanner/.codex/auth.json")
				.bind_ro(codex_dir.join("config.toml"), "/home/scanner/.codex/config.toml");
		}

		let mut cmd = sandbox.build(&self.bin);
		cmd.arg("exec")
			.arg("--dangerously-bypass-approvals-and-sandbox")
			.arg("--skip-git-repo-check")
			.arg(&req.prompt);
		cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

		let mut child = cmd
			.spawn()
			.with_context(|| format!("spawning `{}` (is the codex CLI installed?)", self.bin))?;

		let stdout_handle = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
		let stderr_handle = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

		let cancel = req.cancel.clone();
		let wait_fut = async move {
			tokio::select! {
				biased;
				_ = cancel.cancelled() => {
					let _ = child.kill().await;
					Err(anyhow!("cancelled"))
				}
				res = child.wait() => res.map_err(Into::into),
			}
		};

		let (status, stdout, stderr) = match timeout(req.timeout, async {
			let mut stdout_buf = Vec::new();
			let mut stderr_buf = Vec::new();
			let mut so = stdout_handle;
			let mut se = stderr_handle;
			let (status, _, _) = tokio::join!(
				wait_fut,
				so.read_to_end(&mut stdout_buf),
				se.read_to_end(&mut stderr_buf),
			);
			Result::<_>::Ok((status?, stdout_buf, stderr_buf))
		})
		.await
		{
			Ok(inner) => inner?,
			Err(_) => return Err(anyhow!("codex CLI timed out after {:?}", req.timeout)),
		};

		if !status.success() {
			let stderr_text = String::from_utf8_lossy(&stderr);
			let stdout_text = String::from_utf8_lossy(&stdout);
			tracing::debug!(
				backend = BACKEND_ID,
				exit = ?status.code(),
				stdout_chars = stdout.len(),
				stderr_chars = stderr.len(),
				elapsed_ms = started.elapsed().as_millis() as u64,
				"codex-cli: subprocess failed",
			);
			let combined = format!(
				"stderr=`{}` stdout=`{}`",
				truncate(&stderr_text, 400),
				truncate(&stdout_text, 400),
			);
			return Err(anyhow!("codex CLI exited with {}: {}", status, combined));
		}

		let text = String::from_utf8(stdout)
			.map_err(|e| anyhow!("codex CLI stdout was not UTF-8: {e}"))?;
		tracing::debug!(
			backend = BACKEND_ID,
			elapsed_ms = started.elapsed().as_millis() as u64,
			stdout_chars = text.chars().count(),
			stderr_chars = stderr.len(),
			"codex-cli: subprocess succeeded",
		);
		Ok(LlmResponse { text, backend_id: BACKEND_ID })
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio_util::sync::CancellationToken;

	use super::*;

	fn codex_present(bin: &str) -> bool {
		std::process::Command::new(bin)
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	fn bwrap_present() -> bool {
		std::process::Command::new("bwrap")
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	#[tokio::test]
	async fn cli_backend_round_trip_against_real_codex() {
		// Live test: needs `codex` + `bwrap` and either an
		// `OPENAI_API_KEY` in env or a `~/.codex/auth.json` from
		// `codex login`. The auth dir is bind-mounted read-only into
		// the sandbox, so OAuth flows that would write back token-
		// refresh state can fail; in practice codex's refresh updates
		// the file *before* the call and the in-memory token survives
		// the session. Skip if either binary is missing or no auth
		// material is present — same shape as the claude live test.
		if !codex_present("codex") || !bwrap_present() {
			eprintln!("skipping: codex or bwrap missing");
			return;
		}
		let auth_present = std::env::var_os("OPENAI_API_KEY").is_some()
			|| std::env::var_os("HOME").is_some_and(|h| {
				std::path::PathBuf::from(h).join(".codex").join("auth.json").exists()
			});
		if !auth_present {
			eprintln!("skipping: no OPENAI_API_KEY and no ~/.codex/auth.json");
			return;
		}

		let workdir = tempfile::tempdir().unwrap();
		let backend = CodexCliBackend::new();
		let req = LlmRequest {
			prompt: "Reply with only the single word `pong`. No prose, no formatting.".to_owned(),
			workdir: workdir.path().to_path_buf(),
			// Live LLM call — give it generous headroom; codex's first-
			// turn warm-up can take a few seconds.
			timeout: Duration::from_secs(120),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
		};
		let resp = backend.run(req).await.expect("codex responded");
		assert_eq!(resp.backend_id, BACKEND_ID);
		assert!(!resp.text.trim().is_empty());
	}

	#[tokio::test]
	async fn missing_binary_errors_clearly() {
		// `loupe-worker-no-such-bin` definitely does not exist on PATH.
		let workdir = tempfile::tempdir().unwrap();
		let backend = CodexCliBackend::with_bin("loupe-worker-no-such-bin");
		let req = LlmRequest {
			prompt: "irrelevant".into(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
		};
		let err = backend.run(req).await.expect_err("must error");
		let msg = err.to_string().to_lowercase();
		assert!(
			msg.contains("spawn")
				|| msg.contains("loupe-worker-no-such-bin")
				|| msg.contains("not found")
				|| msg.contains("no such")
				|| msg.contains("exited")
				|| msg.contains("preparing sandbox"),
			"unexpected error: {err}"
		);
	}
}
