//! Mid-flight certificate revocation test (issue #394).

use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::http_client;
use super::svid::TlsIdentity;

struct TestCa {
    cert: Certificate,
    key: KeyPair,
}

fn make_ca() -> TestCa {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, "tessera-test-ca");
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCa { cert, key }
}

fn issue(
    ca: &TestCa,
    san: &str,
    usage: ExtendedKeyUsagePurpose,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, san);
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

fn server_config(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}

/// A peer that revokes the client certificate closes the established
/// connection; the client must observe that within the 10 s requirement.
#[tokio::test]
async fn revoked_certificate_terminates_the_connection_within_ten_seconds() {
    let ca = make_ca();
    let ca_der = ca.cert.der().clone();
    let (server_cert, server_key) = issue(&ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) =
        issue(&ca, "tessera-api", ExtendedKeyUsagePurpose::ClientAuth);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = server_config(&ca_der, server_cert, server_key);

    let (revoke_tx, mut revoke_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(config)
            .accept(stream)
            .await
            .expect("client certificate rejected");

        // Hold the request open until the test revokes the identity.
        let mut request = [0u8; 64];
        let _ = tls.read(&mut request).await;
        tls.write_all(b"H").await.unwrap();

        tokio::select! {
            _ = revoke_rx.changed() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
        // Dropping `tls` closes the socket, which is what a peer enforcing a
        // revocation list does to an established session.
    });

    let identity = TlsIdentity {
        cert_chain: vec![client_cert],
        private_key: client_key,
        roots: vec![ca_der],
    };
    let connector = TlsConnector::from(Arc::new(http_client::client_config(&identity).unwrap()));
    let stream = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = connector.connect(name, stream).await.unwrap();

    tls.write_all(b"GET /hold HTTP/1.1\r\n\r\n").await.unwrap();
    let mut ack = [0u8; 1];
    assert_eq!(tls.read(&mut ack).await.unwrap(), 1);

    let started = Instant::now();
    revoke_tx.send(true).unwrap();

    let mut rest = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut rest)).await;
    assert!(
        outcome.is_ok(),
        "the connection was not terminated within 10s of the certificate being revoked"
    );
    assert!(started.elapsed() < Duration::from_secs(10));

    server.await.unwrap();
}
