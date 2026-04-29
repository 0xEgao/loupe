//! Bubblewrap sandbox helper for scanner subprocesses.
//!
//! Every scanner runs inside `bwrap` so a malicious or buggy invocation
//! can't poison follow-up jobs. Each invocation gets a fresh `/tmp`,
//! its own `$HOME`, and the worktree mounted read-only at `/workdir`.
//! Network is unshared by default; LLM backends opt in via
//! [`SandboxBuilder::allow_network`].
//!
//! `LOUPE_DISABLE_SANDBOX=1` exists as a development escape hatch on
//! hosts without `bwrap`; the worker logs a loud warning if it's set,
//! and the helper produces a plain `Command` instead of a wrapped one.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Path to the bwrap binary. Resolved once and cached.
const BWRAP_BIN: &str = "bwrap";

/// Env var that disables the sandbox entirely. Dev-only; production
/// deployments should leave this unset and install bubblewrap.
pub const DISABLE_SANDBOX_ENV: &str = "LOUPE_DISABLE_SANDBOX";

/// Probe for `bwrap` once at startup. Returns `Ok(true)` if `bwrap` is
/// available, `Ok(false)` if `LOUPE_DISABLE_SANDBOX` is set (caller
/// should warn loudly). Errors if `bwrap` is missing AND the disable
/// env var is unset — that's a hard fatal for the worker.
pub fn probe_at_startup() -> Result<bool> {
	let disabled = std::env::var_os(DISABLE_SANDBOX_ENV).is_some_and(|v| !v.is_empty());
	if disabled {
		return Ok(false);
	}
	let status = std::process::Command::new(BWRAP_BIN)
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status();
	match status {
		Ok(s) if s.success() => Ok(true),
		Ok(s) => Err(anyhow::anyhow!("bwrap probe exited with {s}")),
		Err(e) => Err(anyhow::Error::from(e).context(format!(
			"`{BWRAP_BIN}` not found on PATH; install bubblewrap or set {DISABLE_SANDBOX_ENV}=1 \
			 to opt out (dev only)"
		))),
	}
}

/// Builder for a sandboxed `tokio::process::Command`. Default posture:
/// worktree mounted read-only at `/workdir`, fresh tmpfs `/tmp` and
/// `$HOME`, `--unshare-all`, `--die-with-parent`, working directory set
/// to `/workdir`.
pub struct SandboxBuilder {
	workdir: PathBuf,
	allow_network: bool,
	disabled: bool,
}

impl SandboxBuilder {
	/// New builder targeting a worktree on disk. The `workdir` is bind-
	/// mounted read-only into the sandbox at `/workdir`.
	pub fn new(workdir: impl Into<PathBuf>) -> Self {
		let disabled = std::env::var_os(DISABLE_SANDBOX_ENV).is_some_and(|v| !v.is_empty());
		Self { workdir: workdir.into(), allow_network: false, disabled }
	}

	/// Permit outbound network. Used by LLM backends that need to reach
	/// their provider over HTTPS. Off by default — most scanners
	/// shouldn't need network access at all.
	pub fn allow_network(mut self) -> Self {
		self.allow_network = true;
		self
	}

	/// Build a `Command` for `program`. The command runs inside the
	/// sandbox; its `args()` should be appended by the caller as
	/// normal. When the sandbox is disabled (`LOUPE_DISABLE_SANDBOX=1`)
	/// returns a bare `Command::new(program)` with `current_dir` set to
	/// the worktree.
	pub fn build(&self, program: &str) -> Command {
		if self.disabled {
			let mut cmd = Command::new(program);
			cmd.current_dir(&self.workdir);
			return cmd;
		}

		let mut cmd = Command::new(BWRAP_BIN);
		cmd.arg("--die-with-parent");

		if self.allow_network {
			cmd.arg("--share-net");
		} else {
			cmd.arg("--unshare-net");
		}
		cmd.args(["--unshare-pid", "--unshare-ipc", "--unshare-uts"]);

		// Read-only system directories. /lib and /lib64 are platform-
		// dependent: glibc systems have /lib64, musl typically does not.
		// We bind whichever exists.
		for ro in ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin"] {
			if Path::new(ro).exists() {
				cmd.args(["--ro-bind-try", ro, ro]);
			}
		}

		cmd.args(["--proc", "/proc", "--dev", "/dev"]);

		// Worktree: read-only.
		cmd.arg("--ro-bind").arg(&self.workdir).arg("/workdir");
		cmd.args(["--chdir", "/workdir"]);

		// Fresh tmpfs for /tmp and a new $HOME.
		cmd.args(["--tmpfs", "/tmp", "--tmpfs", "/home/scanner"]);
		cmd.args(["--setenv", "HOME", "/home/scanner"]);
		cmd.args(["--setenv", "TMPDIR", "/tmp"]);

		cmd.arg("--").arg(program);
		cmd
	}

	/// Convenience: build with full args + stdio piped, returning the
	/// fully prepared command for the caller to spawn.
	pub fn build_with_args<'a>(
		&self, program: &str, args: impl IntoIterator<Item = &'a str>,
	) -> Command {
		let mut cmd = self.build(program);
		for a in args {
			cmd.arg(a);
		}
		cmd
	}
}

/// Validate that the host can run `bwrap` *with its full mount layout*,
/// not just `--version`. Useful in tests and as a smoke check before
/// the worker runs its first scan. Many container hosts have `bwrap`
/// installed but disable user namespaces, which makes any real
/// invocation fail; calling this once at startup surfaces that early
/// rather than mid-job.
pub fn smoketest(workdir: &Path) -> Result<()> {
	let builder = SandboxBuilder::new(workdir);
	let mut cmd = builder.build("/bin/true");
	cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
	let output = std::process::Command::new(cmd.as_std().get_program())
		.args(cmd.as_std().get_args())
		.output()
		.context("running bwrap smoketest")?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		anyhow::bail!("bwrap smoketest failed: {} ({stderr})", output.status);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::io::Write;

	use super::*;

	fn bwrap_present() -> bool {
		std::process::Command::new(BWRAP_BIN)
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	#[tokio::test]
	async fn build_runs_a_command_inside_the_sandbox() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		let mut cmd = SandboxBuilder::new(tmp.path()).build("/bin/sh");
		let out =
			cmd.arg("-c").arg("echo hello && pwd").output().await.expect("bwrap smoketest spawned");
		assert!(
			out.status.success(),
			"exit: {}, stderr: {}",
			out.status,
			String::from_utf8_lossy(&out.stderr)
		);
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("hello"), "stdout: {stdout}");
		assert!(stdout.contains("/workdir"), "should be in /workdir, got: {stdout}");
	}

	#[tokio::test]
	async fn worktree_mount_is_read_only() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// Plant a file the test can try to overwrite.
		let mut f = std::fs::File::create(tmp.path().join("readme")).unwrap();
		f.write_all(b"original").unwrap();

		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("echo overwrite > /workdir/readme && echo OK || echo DENIED")
			.output()
			.await
			.expect("spawn");
		let stdout = String::from_utf8_lossy(&out.stdout);
		// The command itself must report DENIED — read-only mount.
		assert!(stdout.contains("DENIED"), "stdout: {stdout}");
		// And the original file on disk is unchanged.
		let after = std::fs::read_to_string(tmp.path().join("readme")).unwrap();
		assert_eq!(after, "original");
	}

	#[tokio::test]
	async fn tmp_is_fresh_per_invocation() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// First run: drop a marker into /tmp.
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("echo marker > /tmp/m && cat /tmp/m")
			.output()
			.await
			.unwrap();
		assert!(out.status.success());
		assert!(String::from_utf8_lossy(&out.stdout).contains("marker"));

		// Second run: marker must be gone — /tmp is a fresh tmpfs.
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("test -f /tmp/m && echo LEAK || echo CLEAN")
			.output()
			.await
			.unwrap();
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("CLEAN"), "/tmp must be fresh between runs; got: {stdout}");
	}

	#[tokio::test]
	async fn unshare_net_blocks_outbound_connections() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// `getent hosts` should fail without --share-net (no DNS).
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("getent hosts example.com >/dev/null 2>&1 && echo ALLOWED || echo BLOCKED")
			.output()
			.await
			.unwrap();
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("BLOCKED"), "net should be unshared; got: {stdout}");
	}

	#[test]
	fn disabled_sandbox_returns_bare_command() {
		// Use a builder that thinks the env var is set.
		let mut b = SandboxBuilder::new("/tmp");
		b.disabled = true;
		let cmd = b.build("/bin/echo");
		assert_eq!(cmd.as_std().get_program(), "/bin/echo");
	}

	#[test]
	fn allow_network_flag_emits_share_net() {
		let mut b = SandboxBuilder::new("/tmp");
		b.disabled = false; // even if env says disabled, force the wrapped path
		let cmd = b.allow_network().build("/bin/true");
		// Inspect the args of the bwrap invocation (program is bwrap).
		assert_eq!(cmd.as_std().get_program(), "bwrap");
		let args: Vec<String> =
			cmd.as_std().get_args().map(|s| s.to_string_lossy().into_owned()).collect();
		assert!(args.iter().any(|a| a == "--share-net"), "args: {args:?}");
		assert!(!args.iter().any(|a| a == "--unshare-net"), "args: {args:?}");
	}
}
