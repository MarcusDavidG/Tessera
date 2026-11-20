//! `sqlx` TLS options carrying the SVID as the PostgreSQL client certificate.

use sqlx::postgres::{PgConnectOptions, PgSslMode};

use super::SvidMaterial;

/// Attach the SVID and the SPIFFE trust bundle to a Postgres connection.
///
/// `VerifyFull` makes the client verify both the server certificate against
/// the SPIFFE bundle and the hostname; sqlx reads the inline PEM when it opens
/// each connection, so a pool created after a rotation uses the new SVID.
/// Connections already established keep their handshake (and therefore keep
/// serving) until they are recycled.
pub fn apply(options: PgConnectOptions, material: &SvidMaterial) -> PgConnectOptions {
    options
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(material.roots_pem.clone())
        .ssl_client_cert_from_pem(material.cert_chain_pem.clone())
        .ssl_client_key_from_pem(material.private_key_pem.clone())
}
