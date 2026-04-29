use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;

#[derive(Debug, Parser)]
#[command(version, about = "loupe security-scanning daemon")]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
	/// Run the loupe daemon. Bootstrap the CA + admin cert separately
	/// (the bootstrap subcommand lands in a follow-up commit).
	Serve(ServeArgs),
}

#[derive(Debug, Parser)]
struct ServeArgs {
	#[arg(long, env = "LOUPE_BIND", default_value = "127.0.0.1:8443")]
	bind: SocketAddr,
	#[arg(long, env = "LOUPE_DB")]
	db: PathBuf,
	#[arg(long, env = "LOUPE_SERVER_CERT")]
	server_cert: PathBuf,
	#[arg(long, env = "LOUPE_SERVER_KEY")]
	server_key: PathBuf,
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt::init();
	let cli = Cli::parse();
	match cli.cmd {
		Cmd::Serve(args) => run_serve(args).await,
	}
}

async fn run_serve(args: ServeArgs) -> Result<()> {
	let server_cert_pem = std::fs::read_to_string(&args.server_cert)
		.with_context(|| format!("reading server cert at {}", args.server_cert.display()))?;
	let server_key_pem = std::fs::read_to_string(&args.server_key)
		.with_context(|| format!("reading server key at {}", args.server_key.display()))?;
	let ca_cert_pem = std::fs::read_to_string(&args.ca_cert)
		.with_context(|| format!("reading CA cert at {}", args.ca_cert.display()))?;

	let cfg = Config {
		bind_addr: args.bind,
		db_path: args.db.clone(),
		server_cert_pem,
		server_key_pem,
		ca_cert_pem,
	};
	let db = Db::open(&args.db).with_context(|| format!("opening db at {}", args.db.display()))?;
	let state = AppState::new(Arc::new(db));

	let handle = serve(cfg, state).await?;
	tracing::info!(addr = %handle.local_addr, "loupe-server listening");

	tokio::signal::ctrl_c().await.context("waiting for SIGINT")?;
	tracing::info!("loupe-server shutting down");
	handle.shutdown().await;
	Ok(())
}
