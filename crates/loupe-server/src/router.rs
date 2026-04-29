use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};

use crate::state::AppState;
use crate::{routes, tls, Config};

/// Build the axum `Router` for the server. Public so integration tests
/// can mount it against an in-memory transport without spinning up TLS.
pub fn router(state: AppState) -> Router {
	Router::new().route("/v1/health", get(routes::health::get)).with_state(state).layer(
		axum::middleware::from_fn(|req, next: axum::middleware::Next| async move {
			let mut resp = next.run(req).await;
			resp.headers_mut().insert(
				PROTOCOL_VERSION_HEADER,
				PROTOCOL_VERSION.to_string().parse().expect("u16 parses as header value"),
			);
			resp
		}),
	)
}

/// Handle returned by [`serve`] so callers (and tests) can shut the
/// server down cleanly.
pub struct ServeHandle {
	pub local_addr: SocketAddr,
	pub handle: axum_server::Handle,
	pub join: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl ServeHandle {
	pub async fn shutdown(self) {
		self.handle.shutdown();
		let _ = self.join.await;
	}
}

/// Bind to `cfg.bind_addr` and serve the router over mTLS. Returns once
/// the listener is actually bound so callers (and tests) can read
/// `local_addr` without races.
pub async fn serve(cfg: Config, state: AppState) -> Result<ServeHandle> {
	let rustls_cfg = tls::build(&cfg)?;
	let tls = RustlsConfig::from_config(Arc::new(rustls_cfg));
	let app = router(state).into_make_service();

	let handle = axum_server::Handle::new();
	let bind = cfg.bind_addr;

	// Use a std listener so we know the bound address synchronously; hand
	// it to axum-server which will turn it into a tokio listener internally.
	let listener = std::net::TcpListener::bind(bind).context("binding loupe-server")?;
	listener.set_nonblocking(true).context("set_nonblocking on bound listener")?;
	let local_addr = listener.local_addr().context("local_addr on bound listener")?;

	let handle_clone = handle.clone();
	let join = tokio::spawn(async move {
		axum_server::from_tcp_rustls(listener, tls).handle(handle_clone).serve(app).await
	});

	Ok(ServeHandle { local_addr, handle, join })
}
