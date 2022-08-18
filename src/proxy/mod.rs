pub mod err;

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::future;
use mqtt::control::{ControlType, PacketType};
use mqtt::packet::ConnectPacket;
use mqtt::{Decodable, Encodable};
use openssl::ssl::Ssl;

use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tracing::error;

use crate::cfssl::Pki;
use err::ConnectionError;

extern crate mqtt;

pub struct Proxy {
    acceptor: openssl::ssl::SslAcceptor,
    upstream_addr: String,
    pub peer_cert_as_clientid: bool,
    pub peer_cert_as_username: bool,
    pki: Arc<Mutex<Pki>>,
}

impl Proxy {
    pub async fn new(
        crl_url: &str,
        crl_update_interval: u64,
        tls_definition: &String,
        upstream_addr: &String,
        peer_cert_as_clientid: bool,
        peer_cert_as_username: bool,
    ) -> Result<Arc<Proxy>, ConnectionError> {
        let mut sslb = openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls())?;

        let pki = Pki::new_with_crl_refresh(tls_definition, true, crl_url, crl_update_interval)
            .await
            .unwrap();

        {
            let p_lock = pki.lock().unwrap();

            sslb.set_private_key_file(p_lock.key_path.clone(), openssl::ssl::SslFiletype::PEM)?;
            sslb.set_certificate_chain_file(p_lock.bundle_path.clone())?;
            let ca = X509::from_pem(p_lock.ca_certificate.as_bytes()).unwrap();
            let mut store_bldr = X509StoreBuilder::new().unwrap();
            store_bldr.add_cert(ca).unwrap();
            sslb.set_verify_cert_store(store_bldr.build())?;
            sslb.check_private_key()?;
        }
        // accept all certificates, we'll do our own validation on them
        sslb.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |succeeded, _| succeeded);
        sslb.set_verify_depth(3);
        // sslb.set_session_id_context()

        let acceptor = sslb.build();
        let proxy = Proxy {
            acceptor,
            upstream_addr: upstream_addr.to_string(),
            peer_cert_as_clientid,
            peer_cert_as_username,
            pki,
        };

        Ok(Arc::new(proxy))
    }

    fn authenticate_certificate(
        ssl: &openssl::ssl::SslRef,
        crl: Arc<Mutex<Pki>>,
    ) -> Result<String, ConnectionError> {
        fn is_before(
            x: &openssl::asn1::Asn1TimeRef,
            y: &openssl::asn1::Asn1TimeRef,
        ) -> Result<bool, ConnectionError> {
            match x.diff(y) {
                Ok(time_diff) => Ok(time_diff.days > 0 || time_diff.secs > 0),
                Err(_) => Err(ConnectionError::InvalidTimeFormat),
            }
        }

        fn is_valid_time(peer: &openssl::x509::X509) -> Result<(), ConnectionError> {
            let now = openssl::asn1::Asn1Time::days_from_now(0)?;

            if is_before(&now, peer.not_before())? {
                return Err(ConnectionError::ClientCertNotYetValid {
                    date: peer.not_before().to_string(),
                });
            }

            if is_before(peer.not_after(), &now)? {
                return Err(ConnectionError::ClientCertExpired {
                    date: peer.not_after().to_string(),
                });
            }

            Ok(())
        }

        fn get_common_name(peer: &openssl::x509::X509) -> String {
            peer.subject_name()
                .entries()
                .last()
                .map(|it| {
                    it.data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "".to_string())
                })
                .unwrap_or_else(|| "<Unknown>".to_string())
        }

        match ssl.peer_certificate() {
            None => Err(ConnectionError::InvalidCertiicateCert),
            Some(peer) => {
                let common_name = get_common_name(&peer);

                let serial = peer.serial_number().to_bn().unwrap().to_string();

                {
                    let crl_c = crl.lock().unwrap();
                    if crl_c.contains_key(&serial) {
                        error!("Certificate {} is revoked", serial);
                        return Err(ConnectionError::CertificateRevoked);
                    }
                }

                match is_valid_time(&peer) {
                    Ok(_) => Ok(common_name),
                    Err(e) => Err(e),
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        connection: TcpStream,
    ) -> std::result::Result<(), ConnectionError> {
        let ssl = Ssl::new(self.acceptor.context()).unwrap();
        let mut stream = SslStream::new(ssl, connection).unwrap();

        match Pin::new(&mut stream).accept().await {
            Ok(()) => match Proxy::authenticate_certificate(stream.ssl(), self.pki.clone()) {
                Ok(common_name) => Proxy::transfer(self, &mut stream, common_name).await?,
                Err(e) => error!("Failed to transfer: {}", e),
            },
            Err(e) => error!("Error accepting connection: {}", e),
        }

        Ok(())
    }

    pub async fn accept_connections(
        proxy: Arc<Proxy>,
        downstream_listener: TcpListener,
    ) -> Result<(), io::Error> {
        loop {
            match downstream_listener.accept().await {
                Ok((conn, _)) => {
                    let pxy = proxy.clone();
                    tokio::spawn(async move {
                        match pxy.handle_connection(conn).await {
                            Ok(()) => (),
                            Err(e) => error!("{}", e),
                        }
                    });
                }
                Err(e) => error!("Connection error: {}", e),
            }
        }
    }

    async fn transfer(
        &self,
        downstream: &mut SslStream<TcpStream>,
        common_name: String,
    ) -> Result<(), ConnectionError> {
        let (mut downstream_reader, mut downstream_writer) = tokio::io::split(downstream);

        // Connect to the upstream server
        let mut upstream = TcpStream::connect(self.upstream_addr.to_string()).await?;
        let (mut upstream_reader, mut upstream_writer) = upstream.split();

        let downstream_to_upstream = async {
            let mut read_done = false;
            let (mut pos, mut cap) = (0, 0);
            let mut buf = vec![0; 2048].into_boxed_slice();

            loop {
                // If our buffer is empty, then we need to read some data to
                // continue.
                if pos == cap && !read_done {
                    let n = downstream_reader.read(&mut buf).await?;

                    if n == 0 {
                        read_done = true;
                    } else {
                        pos = 0;
                        cap = n;
                    }
                }

                // Determine packet type
                if let Ok(packet_type) = PacketType::from_u8(buf[0]) {
                    if let ControlType::Connect = packet_type.control_type() {
                        // Inject common_name as username
                        let mut cursor = Cursor::new(&buf[..]);
                        let mut packet = ConnectPacket::decode(&mut cursor).unwrap();
                        let mut buf_vec = vec![];

                        if self.peer_cert_as_username {
                            packet.set_user_name(Some(common_name.to_owned()));
                        }
                        if self.peer_cert_as_clientid {
                            packet.set_client_identifier(common_name.to_owned());
                        }
                        packet.encode(&mut buf_vec).unwrap();
                        cap = buf_vec.len();
                        buf = buf_vec.into_boxed_slice();
                    }
                }

                // If our buffer has some data, let's write it out!
                while pos < cap {
                    let i = upstream_writer.write(&buf[pos..cap]).await?;

                    if i == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero byte into writer",
                        ));
                    } else {
                        pos += i;
                    }
                }

                // If we've written all the data and we've seen EOF, flush out the
                // data and finish the transfer.
                if pos == cap && read_done {
                    upstream_writer.flush().await?;
                    upstream_writer.shutdown().await?;

                    return Ok(());
                }
            }
        };

        let upstream_to_downstream =
            async { tokio::io::copy(&mut upstream_reader, &mut downstream_writer).await };

        future::try_join(downstream_to_upstream, upstream_to_downstream).await?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use openssl::x509::X509;

    #[tokio::test]
    #[ignore]
    async fn check_revoked() {
        let cert = include_bytes!("../../server.pem");
        let cert = X509::from_pem(cert).unwrap();
        let ca = include_bytes!("../../../assets/pki/ca.pem");
        let ca = X509::from_pem(ca).unwrap();

        println!("{}", cert.serial_number().to_bn().unwrap());
        println!("{}", cert.public_key().unwrap().id().as_raw());
    }
}
