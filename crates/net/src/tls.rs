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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fail {
    Refused,
    Unreachable,
    TcpTimeout,
    TlsReset,
    TlsTimeout,
    TlsOther,
}

impl Fail {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::TcpTimeout => "tcp-timeout",
            Self::TlsReset => "tls-reset",
            Self::TlsTimeout => "tls-timeout",
            Self::TlsOther => "tls-error",
        }
    }

    pub fn retries(self) -> usize {
        match self {
            Self::Refused | Self::Unreachable | Self::TlsOther => 0,
            Self::TcpTimeout | Self::TlsTimeout => 1,
            Self::TlsReset => 4,
        }
    }
}

fn tcp_fail(e: &std::io::Error) -> Fail {
    use std::io::ErrorKind::{ConnectionRefused, HostUnreachable, NetworkUnreachable, TimedOut};
    match e.kind() {
        ConnectionRefused => Fail::Refused,
        HostUnreachable | NetworkUnreachable => Fail::Unreachable,
        TimedOut => Fail::TcpTimeout,
        _ => Fail::Unreachable,
    }
}

fn tls_fail(e: &std::io::Error) -> Fail {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof,
    };
    match e.kind() {
        ConnectionReset | ConnectionAborted | UnexpectedEof | BrokenPipe => Fail::TlsReset,
        TimedOut => Fail::TlsTimeout,
        _ => Fail::TlsOther,
    }
}

pub async fn connect(
    connector: &TlsConnector,
    host: &str,
    ip: IpAddr,
    tcp_timeout: Duration,
    tls_timeout: Duration,
) -> Result<TlsStream<TcpStream>, Fail> {
    let name = ServerName::try_from(host.to_string()).unwrap_or(ServerName::IpAddress(ip.into()));
    let tcp = tokio::time::timeout(tcp_timeout, TcpStream::connect(SocketAddr::new(ip, 443)))
        .await
        .map_err(|_| Fail::TcpTimeout)?
        .map_err(|e| tcp_fail(&e))?;
    let _ = tcp.set_nodelay(true);
    tokio::time::timeout(tls_timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| Fail::TlsTimeout)?
        .map_err(|e| tls_fail(&e))
}

pub fn print<S>(stream: &TlsStream<S>) -> String {
    let c = stream.get_ref().1;
    let version = c
        .protocol_version()
        .map_or("-".to_string(), |v| format!("{v:?}"));
    let cipher = c
        .negotiated_cipher_suite()
        .map_or("-".to_string(), |s| format!("{:?}", s.suite()));
    let alpn = c
        .alpn_protocol()
        .map_or("-".to_string(), |a| String::from_utf8_lossy(a).into_owned());
    let chain = c.peer_certificates().map_or(0, <[_]>::len);
    format!("{version}|{cipher}|{alpn}|{chain}")
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
