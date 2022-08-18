use anyhow::Error;
use std::sync::Arc;

use crate::config::Settings;
use crate::proxy::Proxy;
use futures::FutureExt;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGKILL;
use signal_hook::iterator::exfiltrator::WithOrigin;
use signal_hook::iterator::SignalsInfo;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod cfssl;
pub mod config;
mod proxy;

/// Listen for interrupts to gracefully kill the daemon
#[tracing::instrument]
async fn sigint_notifier() {
    let mut signals = SignalsInfo::<WithOrigin>::new(&[SIGINT]).unwrap_or_else(|e| {
        panic!("{}", e);
    });
    for info in &mut signals {
        warn!("Received a signal {:?}", info);
        match info.signal {
            SIGINT => {
                break;
            }
            SIGKILL => {
                break;
            }
            _ => {}
        }
    }
}

// Run a TLS listener, accept new connections and redirect them to a MQTT
// server
async fn run_proxy(
    proxy: Arc<Proxy>,
    downstream_addr: &String,
    upstream_addr: &String,
) -> Result<(), Error> {
    let downstream_listener = TcpListener::bind(downstream_addr).await?;

    info!("Listening on: {}", downstream_addr);
    info!("Proxying to: {}", upstream_addr);
    Proxy::accept_connections(proxy, downstream_listener)
        .map(|_| ())
        .await;

    Ok(())
}

/// Main entry for the app, will perform many steps and spawn essential tasks
///
/// # Arguments
///
/// * `config` - Configuration object
#[tracing::instrument(skip(config))]
pub async fn run(config: Settings) -> Result<(), Error> {
    info!(":::: STARTING MQTT BRIDGE ::::");

    info!("Ready for reaching CRL");

    let in_config = config;

    let proxy = proxy::Proxy::new(
        &in_config.crl_url,
        in_config.crl_update_interval,
        &in_config.tls_definition,
        &in_config.upstream_addr,
        in_config.peer_cert_as_clientid,
        in_config.peer_cert_as_username,
    )
    .await?;

    // Proxy thread
    tokio::spawn(async move {
        run_proxy(proxy, &in_config.downstream_addr, &in_config.upstream_addr)
            .await
            .unwrap();
    });

    sigint_notifier().await;

    Ok(())
}
