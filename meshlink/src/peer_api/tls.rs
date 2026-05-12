use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;

/// Generate an ephemeral self-signed cert for the given hostnames.
pub fn self_signed(
    sans: Vec<String>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let ck = generate_simple_self_signed(sans).context("generating self-signed cert")?;
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    Ok((vec![cert], key))
}

/// Load cert + key from PEM files.
pub fn from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path).context("reading TLS cert")?;
    let key_pem = std::fs::read(key_path).context("reading TLS key")?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<std::result::Result<_, _>>()
            .context("parsing TLS cert PEM")?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parsing TLS key PEM")?
        .context("no private key in key file")?;

    Ok((certs, key))
}

/// Build a rustls ServerConfig. When `mtls_ca_path` is Some, require client certs
/// signed by that CA (mTLS). Otherwise use no client auth.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    mtls_ca_path: Option<&str>,
) -> Result<Arc<ServerConfig>> {
    let cfg = if let Some(ca) = mtls_ca_path {
        let ca_pem = std::fs::read(ca).context("reading mTLS CA cert")?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots.add(cert.context("parsing CA cert")?).context("adding CA cert")?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("building mTLS verifier")?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("building mTLS ServerConfig")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building TLS ServerConfig")?
    };
    Ok(Arc::new(cfg))
}
