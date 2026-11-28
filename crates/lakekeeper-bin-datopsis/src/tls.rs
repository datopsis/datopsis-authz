//! TLS transport around unmodified upstream. Plaintext API and metrics stay on loopback.
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub struct Transport {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}
impl Transport {
    pub async fn from_env() -> anyhow::Result<Self> {
        anyhow::ensure!(
            lakekeeper::CONFIG.bind_ip.is_loopback(),
            "Lakekeeper API and metrics must bind loopback behind the TLS listener"
        );
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            std::env::var("AUTHZ_TLS_CERT")?,
            std::env::var("AUTHZ_TLS_KEY")?,
        )
        .await?;
        let public: SocketAddr = std::env::var("LAKEKEEPER_TLS_LISTEN")
            .unwrap_or("0.0.0.0:8181".into())
            .parse()?;
        let listener = TcpListener::bind(public).await?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(tls.get_inner()),
        })
    }
    pub async fn run(self, backend: SocketAddr) -> anyhow::Result<()> {
        anyhow::ensure!(
            backend.ip().is_loopback(),
            "private backend must be loopback"
        );
        let limit = Arc::new(tokio::sync::Semaphore::new(1024));
        loop {
            let permit = limit.clone().acquire_owned().await?;
            let (socket, _) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(Ok(mut tls)) =
                    tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await
                    && let Ok(Ok(mut upstream)) =
                        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(backend))
                            .await
                {
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                }
            });
        }
    }
}
