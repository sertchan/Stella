use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn insecure_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map(|b| {
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny(provider.clone())))
                .with_no_client_auth()
        })
        .unwrap_or_else(|_| {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
                .with_no_client_auth()
        });
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

pub async fn connect(
    connector: &TlsConnector,
    host: &str,
    ip: IpAddr,
    timeout: Duration,
) -> std::io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(host.to_string()).unwrap_or(ServerName::IpAddress(ip.into()));
    let run = async {
        let tcp = TcpStream::connect(SocketAddr::new(ip, 443)).await?;
        tcp.set_nodelay(true)?;
        connector.connect(name, tcp).await
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

pub fn sans<S>(stream: &TlsStream<S>) -> Vec<String> {
    let Some(der) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
    else {
        return Vec::new();
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref()) else {
        return Vec::new();
    };
    let Ok(Some(ext)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    ext.value
        .general_names
        .iter()
        .filter_map(|g| match g {
            x509_parser::extensions::GeneralName::DNSName(d) => {
                stella_core::name::normalize(d.trim_start_matches("*."))
            }
            _ => None,
        })
        .collect()
}
