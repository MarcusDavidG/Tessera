//! `rustls` client configuration that presents the SVID to peers.

use std::sync::Arc;

use super::svid::TlsIdentity;
use super::SvidError;

/// Build a client TLS configuration that:
///
/// * trusts only the SPIFFE trust bundle (not the public web PKI),
/// * presents the workload's SVID as its client certificate.
pub fn client_config(identity: &TlsIdentity) -> Result<rustls::ClientConfig, SvidError> {
    let mut roots = rustls::RootCertStore::empty();
    for anchor in &identity.roots {
        roots
            .add(anchor.clone())
            .map_err(|error| SvidError::Tls(format!("SPIFFE trust anchor: {error}")))?;
    }

    // Pin the crypto provider instead of relying on the process-wide default:
    // the API links both rustls users (reqwest, sqlx) and must not depend on
    // whichever provider happened to be installed first.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| SvidError::Tls(error.to_string()))?;

    builder
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.cert_chain.clone(), identity.private_key.clone_key())
        .map_err(|error| SvidError::Tls(format!("SVID client certificate: {error}")))
}

/// A `reqwest` client bound to one SVID. The rotation task replaces the whole
/// client on rotation rather than mutating it, so in-flight requests keep the
/// certificate they started with and never see a half-updated configuration.
pub fn build(identity: &TlsIdentity) -> Result<reqwest::Client, SvidError> {
    let config = client_config(identity)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|error| SvidError::Tls(format!("reqwest mTLS client: {error}")))
}
