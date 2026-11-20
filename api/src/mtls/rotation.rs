//! SVID rotation without dropping live connections.

use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use sqlx::postgres::PgConnectOptions;
use tokio::sync::watch;
use tracing::{info, warn};

use super::{http_client, postgres, SvidError, SvidMaterial, SvidSource};

/// Holds the current SVID and the `reqwest` client built from it.
///
/// `arc-swap` gives readers a lock-free snapshot: a request either sees the
/// old client or the new one, never a partially updated pair.
pub struct RotatingSvid {
    source: Arc<SvidSource>,
    client: ArcSwap<reqwest::Client>,
    material: ArcSwapOption<SvidMaterial>,
}

impl RotatingSvid {
    pub fn new(source: Arc<SvidSource>, material: Arc<SvidMaterial>) -> Result<Arc<Self>, SvidError> {
        let client = Arc::new(http_client::build(&material.identity()?)?);
        let rotating = Arc::new(Self {
            source,
            client: ArcSwap::from(client),
            material: ArcSwapOption::empty(),
        });
        rotating.material.store(Some(material));
        Ok(rotating)
    }

    /// The client for the current SVID.
    pub fn http(&self) -> Arc<reqwest::Client> {
        self.client.load_full()
    }

    pub fn material(&self) -> Option<Arc<SvidMaterial>> {
        self.material.load_full()
    }

    /// Postgres options carrying the current SVID.
    pub fn postgres_options(&self, base: PgConnectOptions) -> Option<PgConnectOptions> {
        self.material()
            .map(|material| postgres::apply(base, &material))
    }

    /// Swap in the SVID the source most recently published.
    ///
    /// Returns `true` when a new SVID was applied. The previous client is
    /// dropped only after the swap, so requests already using it complete.
    pub fn refresh(&self) -> Result<bool, SvidError> {
        let material = self.source.current().ok_or(SvidError::NotConfigured)?;
        let unchanged = self
            .material
            .load_full()
            .as_ref()
            .map(|current| current.fingerprint == material.fingerprint)
            .unwrap_or(false);
        if unchanged {
            return Ok(false);
        }

        let client = http_client::build(&material.identity()?)?;
        self.material.store(Some(material));
        self.client.store(Arc::new(client));
        Ok(true)
    }
}

/// Watch the SVID stream and rebuild the client on every rotation.
///
/// `tokio::select!` races the SVID updates against shutdown so a rotation that
/// arrives during termination never blocks the process from exiting.
pub async fn run(
    rotating: Arc<RotatingSvid>,
    mut shutdown: watch::Receiver<bool>,
    mut updates: watch::Receiver<u64>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                info!("SVID rotation task stopping");
                return;
            }
            changed = updates.changed() => {
                if changed.is_err() {
                    return;
                }
                match rotating.refresh() {
                    Ok(true) => info!(
                        "rotated SPIFFE SVID; reqwest client swapped, live connections left open"
                    ),
                    Ok(false) => {}
                    Err(error) => warn!(
                        %error,
                        "SVID rotation failed; keeping the previous client"
                    ),
                }
            }
        }
    }
}
