use std::sync::Once;

static INIT: Once = Once::new();

/// rustls 0.23 requires a crypto provider to be installed before any
/// `ServerConfig` / `ClientConfig` builder runs. We pick `ring` and
/// install it lazily so the choice stays a loupe-tls implementation
/// detail and tests don't have to call init themselves.
///
/// We deliberately don't use `aws-lc-rs` (rustls's other built-in
/// option) — pulling it in vendors a multi-MB LibCrypto fork into
/// every loupe binary, and `ring` covers the cipher suites we
/// actually use. The choice is hard-wired here rather than feature-
/// gated to keep all loupe binaries on the same provider.
pub(crate) fn ensure_provider_installed() {
	INIT.call_once(|| {
		// `install_default` returns `Err` only if a provider was already
		// installed by someone else — fine for our purposes.
		let _ = rustls::crypto::ring::default_provider().install_default();
	});
}
