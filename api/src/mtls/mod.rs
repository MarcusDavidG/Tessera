//! SPIFFE/SPIRE workload identity for inter-service mTLS (issue #394).
//!
//! Every Tessera service runs with a SPIRE agent socket mounted at
//! `/run/spire/sockets/agent.sock`. The agent's SPIFFE CSI driver / SDS mount
//! exposes the workload's X.509 SVID as three files:
//!
//! ```text
//! /svids/tls.crt   certificate chain (leaf first)
//! /svids/tls.key   PKCS#8 private key
//! /svids/ca.crt    trust bundle (SPIFFE roots)
//! ```
//!
//! [`SvidSource`] reads them, [`RotatingSvid`] turns them into a
//! `rustls` configuration and a `reqwest` client, and the rotation task
//! watches the SVID stream with `tokio::select!`: when SPIRE writes a new SVID
//! the `reqwest` client is swapped atomically (via `arc-swap`) and existing
//! connections are left untouched, so rotation never interrupts traffic.
//!
//! `sqlx` TLS material is attached to new `PgConnectOptions` from the current
//! SVID; connections already in a pool keep the certificate they handshook
//! with until they are recycled, which is also interruption-free.
//!
//! Set `SPIFFE_SVID_DIR` (default `/svids`) to enable the integration; when
//! the directory is absent the API starts without mTLS, exactly as before.

mod http_client;
mod postgres;
mod rotation;
mod svid;

#[cfg(test)]
mod tests;

pub use rotation::RotatingSvid;
pub use svid::{SvidError, SvidMaterial, SvidSource, TlsIdentity};

use std::sync::{Arc, OnceLock};

use tokio::sync::watch;
use tracing::{info, warn};

static ACTIVE: OnceLock<Arc<RotatingSvid>> = OnceLock::new();

/// A `reqwest` client presenting the current SVID, if mTLS is enabled.
pub fn http_client() -> Option<reqwest::Client> {
    ACTIVE.get().map(|rotating| (*rotating.http()).clone())
}

/// Attach the current SVID to `options`, if mTLS is enabled.
pub fn postgres_tls(
    options: sqlx::postgres::PgConnectOptions,
) -> Option<sqlx::postgres::PgConnectOptions> {
    ACTIVE
        .get()
        .and_then(|rotating| rotating.postgres_options(options))
}

/// Load the workload SVID and start the rotation tasks.
///
/// Returns `None` (and logs) when this pod has no SPIFFE identity; the caller
/// keeps running without mTLS so local development and CI are unaffected.
pub fn init(shutdown: watch::Receiver<bool>) -> Option<Arc<RotatingSvid>> {
    let source = Arc::new(SvidSource::from_env()?);
    if let Err(error) = source.reload() {
        warn!(%error, "SPIFFE SVID load failed; inter-service mTLS stays disabled");
        return None;
    }
    let material = source.current()?;
    let rotating = match RotatingSvid::new(Arc::clone(&source), material) {
        Ok(rotating) => rotating,
        Err(error) => {
            warn!(%error, "building the mTLS client failed; inter-service mTLS stays disabled");
            return None;
        }
    };

    let updates = source.subscribe();
    tokio::spawn(Arc::clone(&source).watch(shutdown.clone()));
    tokio::spawn(rotation::run(Arc::clone(&rotating), shutdown, updates));

    let spiffe_id = rotating
        .material()
        .map(|material| material.spiffe_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let _ = ACTIVE.set(Arc::clone(&rotating));
    info!(%spiffe_id, "inter-service mTLS enabled with the SPIFFE X.509 SVID");
    Some(rotating)
}
