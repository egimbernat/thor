use config::{Config, ConfigError, Environment, File};
use serde::Serialize;
use std::path::Path;

extern crate toml;

#[derive(Serialize, serde_derive::Deserialize, Clone, Debug, Default)]
pub struct Settings {
    pub logging_level: String,
    pub(crate) crl_url: String,
    pub(crate) tls_definition: String,
    pub(crate) crl_update_interval: u64,
    pub(crate) downstream_addr: String,
    pub(crate) upstream_addr: String,
    pub(crate) peer_cert_as_username: bool,
    pub(crate) peer_cert_as_clientid: bool,
}

impl Settings {
    #[tracing::instrument]
    pub fn new(config_path: String) -> Result<Self, ConfigError> {
        let s = Config::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::from(Path::new(&config_path)))
            // Add in a local configuration file
            // This file shouldn't be checked in to git
            .add_source(File::with_name("local-config").required(false))
            .add_source(Environment::with_prefix("TH"))
            .build()
            .unwrap();

        s.try_deserialize()
    }
}
