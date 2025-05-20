use rustls_pki_types::InvalidDnsNameError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error")]
    Error,
    #[error("Can't load a certificate: {0}")]
    CertLoadError(rustls_pki_types::pem::Error),
    #[error("Could not TLS handshake: {0}")]
    TlsHandshakeError(InvalidDnsNameError),
    #[error("data not upgrade to TLS: {0}")]
    CouldNotUpgradeToTls(std::io::Error),
    #[error("Can't load a key: {0}")]
    KeyLoadError(rustls_pki_types::pem::Error),
    #[error("Could not connect through TCP: {0}")]
    TcpCouldNotConnect(std::io::Error),
    // #[error("Websocket send: {0}")]
    // WsCantSend(tungstenite::Error),
    // #[error("Websocket read: {0}")]
    // WsCantRead(tungstenite::Error),
    #[error("Can't build tls config: {0}")]
    TlsConfigBuildError(rustls::Error),
}
