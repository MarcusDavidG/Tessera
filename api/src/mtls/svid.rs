//! X.509 SVID material and the SPIFFE SDS mount it is read from.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

/// Default SPIFFE CSI/SDS mount used by the SPIRE agent.
const DEFAULT_SVID_DIR: &str = "/svids";
/// How often the SVID mount is stat-ed for rotation. SPIRE rotates roughly
/// every hour; 30 s keeps the window between a new SVID and its use small.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Errors from loading or applying SPIFFE identity material.
#[derive(Debug, thiserror::Error)]
pub enum SvidError {
    #[error("no SPIFFE SVID directory is configured")]
    NotConfigured,
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid SVID material: {0}")]
    Invalid(String),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
}

/// A parsed SVID ready to hand to `rustls`/`sqlx`.
pub struct TlsIdentity {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub roots: Vec<CertificateDer<'static>>,
}

/// The workload's X.509 SVID plus the SPIFFE trust bundle, as PEM.
#[derive(Clone, Debug)]
pub struct SvidMaterial {
    pub spiffe_id: String,
    pub cert_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub roots_pem: Vec<u8>,
    /// SHA-256 of the leaf certificate, used to detect rotation.
    pub fingerprint: String,
}

impl SvidMaterial {
    pub fn from_pems(
        spiffe_id: impl Into<String>,
        cert_chain_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
        roots_pem: Vec<u8>,
    ) -> Result<Self, SvidError> {
        let material = Self {
            spiffe_id: spiffe_id.into(),
            cert_chain_pem,
            private_key_pem,
            roots_pem,
            fingerprint: String::new(),
        };
        let identity = material.identity()?;
        let leaf = identity
            .cert_chain
            .first()
            .ok_or_else(|| SvidError::Invalid("SVID certificate chain is empty".into()))?;
        let fingerprint = hex::encode(Sha256::digest(leaf.as_ref()));
        Ok(Self {
            fingerprint,
            ..material
        })
    }

    /// Parse the PEM fields into DER for `rustls`.
    pub fn identity(&self) -> Result<TlsIdentity, SvidError> {
        let cert_chain = parse_certs(&self.cert_chain_pem)?;
        if cert_chain.is_empty() {
            return Err(SvidError::Invalid(
                "SVID certificate chain contained no certificates".into(),
            ));
        }
        let private_key = rustls_pemfile::private_key(&mut &self.private_key_pem[..])
            .map_err(|error| SvidError::Invalid(format!("SVID private key: {error}")))?
            .ok_or_else(|| SvidError::Invalid("SVID private key file contained no key".into()))?;
        let roots = parse_certs(&self.roots_pem)?;
        if roots.is_empty() {
            return Err(SvidError::Invalid(
                "SPIFFE trust bundle contained no certificates".into(),
            ));
        }
        Ok(TlsIdentity {
            cert_chain,
            private_key,
            roots,
        })
    }
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, SvidError> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| SvidError::Invalid(format!("certificate PEM: {error}")))
}

/// Reads the SVID from the SPIFFE SDS mount and publishes rotations.
pub struct SvidSource {
    dir: PathBuf,
    spiffe_id: String,
    current: ArcSwapOption<SvidMaterial>,
    generation: AtomicU64,
    updates: watch::Sender<u64>,
}

impl SvidSource {
    pub fn new(dir: impl Into<PathBuf>, spiffe_id: impl Into<String>) -> Self {
        let (updates, _) = watch::channel(0u64);
        Self {
            dir: dir.into(),
            spiffe_id: spiffe_id.into(),
            current: ArcSwapOption::empty(),
            generation: AtomicU64::new(0),
            updates,
        }
    }

    /// Enable from the environment. Returns `None` when the SVID mount is not
    /// present, which is the normal case outside Kubernetes.
    pub fn from_env() -> Option<Self> {
        let dir = std::env::var("SPIFFE_SVID_DIR")
            .unwrap_or_else(|_| DEFAULT_SVID_DIR.to_string());
        let path = PathBuf::from(&dir);
        if !path.is_dir() {
            return None;
        }
        let spiffe_id = std::env::var("SPIFFE_ID")
            .unwrap_or_else(|_| "spiffe://tessera.io/ns/prod/sa/tessera-api".to_string());
        Some(Self::new(path, spiffe_id))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Read the current SVID files.
    pub fn load(&self) -> Result<Arc<SvidMaterial>, SvidError> {
        let cert_chain = read(&self.dir.join("tls.crt"))?;
        let private_key = read(&self.dir.join("tls.key"))?;
        let roots = read(&self.dir.join("ca.crt"))?;
        let material =
            SvidMaterial::from_pems(self.spiffe_id.clone(), cert_chain, private_key, roots)?;
        Ok(Arc::new(material))
    }

    /// Re-read the mount and publish the SVID if its leaf changed.
    pub fn reload(&self) -> Result<bool, SvidError> {
        let material = self.load()?;
        let previous = self.current.load_full();
        let unchanged = previous
            .as_ref()
            .map(|previous| previous.fingerprint == material.fingerprint)
            .unwrap_or(false);
        if unchanged {
            return Ok(false);
        }

        self.current.store(Some(Arc::clone(&material)));
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.updates.send(generation);
        info!(
            spiffe_id = %material.spiffe_id,
            fingerprint = %material.fingerprint,
            generation,
            "loaded SPIFFE X.509 SVID"
        );
        Ok(true)
    }

    pub fn current(&self) -> Option<Arc<SvidMaterial>> {
        self.current.load_full()
    }

    /// Subscribe to SVID generation bumps (used by the rotation task).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }

    /// Poll the SDS mount and publish rotations until shutdown.
    pub async fn watch(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("SPIFFE SVID watcher stopping");
                    return;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.reload() {
                        warn!(%error, dir = %self.dir.display(), "SPIFFE SVID refresh failed");
                    }
                }
            }
        }
    }
}

fn read(path: &Path) -> Result<Vec<u8>, SvidError> {
    std::fs::read(path).map_err(|source| SvidError::Io {
        path: path.to_path_buf(),
        source,
    })
}
