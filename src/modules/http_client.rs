//! Outbound HTTP. Every arks `reqwest` client starts from [`builder`], so each
//! https link requires TLS 1.3 (docs/tls.md); plain http, such as the loopback
//! platform, is unaffected.

pub fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().min_tls_version(reqwest::tls::Version::TLS_1_3)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An https server on loopback offering only `version`; answers one 200.
    async fn https_server(version: &'static rustls::SupportedProtocolVersion) -> (u16, Vec<u8>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
        );
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = tls.shutdown().await;
            }
        });
        (port, cert.to_vec())
    }

    async fn get(
        builder: reqwest::ClientBuilder,
        port: u16,
        cert: &[u8],
    ) -> Result<reqwest::StatusCode, reqwest::Error> {
        let client = builder
            .add_root_certificate(reqwest::Certificate::from_der(cert).unwrap())
            .build()
            .unwrap();
        client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .map(|r| r.status())
    }

    #[tokio::test]
    async fn refuses_a_tls12_only_server() {
        let (port, cert) = https_server(&rustls::version::TLS12).await;
        let err = get(super::builder(), port, &cert).await.unwrap_err();
        assert!(err.is_connect(), "{err:?}");
    }

    /// Control for the refusal: the same server works for a client without the minimum,
    /// so the refusal is the TLS version, not the certificate or the server.
    #[tokio::test]
    async fn the_tls12_server_works_without_the_minimum() {
        let (port, cert) = https_server(&rustls::version::TLS12).await;
        let status = get(reqwest::Client::builder(), port, &cert).await.unwrap();
        assert_eq!(status, reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn connects_to_a_tls13_server() {
        let (port, cert) = https_server(&rustls::version::TLS13).await;
        let status = get(super::builder(), port, &cert).await.unwrap();
        assert_eq!(status, reqwest::StatusCode::OK);
    }
}
