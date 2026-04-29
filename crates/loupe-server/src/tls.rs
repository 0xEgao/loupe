use anyhow::{Context, Result};
use loupe_tls::server_config;
use rustls::ServerConfig;

use crate::Config;

/// Build the rustls server config from the PEM material in [`Config`].
pub fn build(cfg: &Config) -> Result<ServerConfig> {
	server_config(&cfg.server_cert_pem, &cfg.server_key_pem, &cfg.ca_cert_pem)
		.context("building loupe-server rustls config")
}
