#[forbid(unsafe_code)]

pub mod error {
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
}

pub mod result {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}

pub mod world {
    use noise::utils::{NoiseMap, PlaneMapBuilder};
    use noise::{core::perlin::perlin_2d, permutationtable::PermutationTable};

    fn generate_noise_map() -> NoiseMap {
        let hasher = PermutationTable::new(0);
        PlaneMapBuilder::new_fn(|point| perlin_2d(point.into(), &hasher))
            .set_size(1024, 1024)
            .set_x_bounds(-5.0, 5.0)
            .set_y_bounds(-5.0, 5.0)
            .build()
    }

    #[derive(Clone)]
    pub enum Block {
        Dirt,
        Stone,
    }

    pub struct Chunk {
        blocks: Vec<Block>,
    }

    impl Chunk {
        pub fn at(&self, x: usize, y: usize) -> Block {
            self.blocks.get(y * 1014 + x).unwrap().clone()
        }
    }

    pub fn generate_chunk() -> Chunk {
        let noise_map = generate_noise_map();

        Chunk {
            blocks: noise_map
                .iter()
                .map(|x| if x < 0 { Block::Dirt } else { Block::Stone })
                .collect(),
        }
    }
}

pub mod network {
    pub mod http {
        use crate::error::Error;
        use crate::game::entity::Entity;
        use crate::instance::Instance;
        use crate::protocol::AuthInfo;
        use crate::protocol::PlayerAction;
        use crate::Id;
        use futures::SinkExt;
        use futures::StreamExt;
        use http_body_util::Full;
        use hyper::body::Bytes;
        use hyper::{Request, Response, StatusCode};
        use hyper_tungstenite::tungstenite::Message;
        use hyper_tungstenite::HyperWebsocket;
        use log::error;
        use log::info;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        use tokio_stream::wrappers::ReceiverStream;
        // extern crate scopeguard;

        use crate::Result;

        pub async fn serve_http(
            mut request: Request<hyper::body::Incoming>,
            instance: Arc<Mutex<Instance>>,
            ws_hdl_sender: crossbeam::channel::Sender<tokio::task::JoinHandle<Result<()>>>,
        ) -> hyper::Result<Response<Full<Bytes>>> {
            let response_body = Full::<Bytes>::new("".into());
            let mut response = Response::<Full<Bytes>>::new(response_body);
            *response.status_mut() = StatusCode::BAD_REQUEST;

            if hyper_tungstenite::is_upgrade_request(&request) {
                info!("Upgrade request");
                let res = hyper_tungstenite::upgrade(&mut request, None);
                if res.is_err() {
                    let err_str: String = res.err().unwrap().to_string();

                    *response.body_mut() = Full::<Bytes>::new(
                        format!("Can't upgrade to websocket: {}", err_str).into(),
                    );

                    info!("WS upgrade error");
                    return Ok(response);
                }

                let (ws_resp, websocket) = res.unwrap();

                let hdl = tokio::spawn(async move {
                    let instance_cln = Arc::clone(&instance);
                    serve_websocket(websocket, instance_cln).await?;
                    Ok(())
                });

                ws_hdl_sender.send(hdl).unwrap();

                return Ok(ws_resp);
            } else {
                *response.body_mut() = Full::<Bytes>::new(format!("Websocket only").into());
                info!("HTTP non WS request");
                return Ok(response);
            }
        }
    }

    pub mod websocket {

        async fn serve_websocket(
            websocket: HyperWebsocket,
            instance: Arc<Mutex<Instance>>,
        ) -> Result<()> {
            let mut websocket = websocket.await.map_err(|_err| Error::Error)?;

            let mut id = Id::MAX;

            let mut authenticated = false;

            // let mut tick_delay = tokio::time::interval(std::time::Duration::from_millis(250));

            let recv = loop {
                tokio::select! {
                    Some(message) = websocket.next() => {
                        if message.is_err() {
                            info!("Websocket read error: {}", message.err().unwrap());
                            if id != u32::MAX {
                                instance.lock().await.leave(id).await?;
                            }
                            return Ok(());
                        }
                        match message.unwrap() {
                            Message::Text(msg) => {
                                let maybe_action: serde_json::Result<PlayerAction> =
                                    serde_json::from_str(msg.as_str());

                                let mut login_info = AuthInfo {
                                    success: false,
                                    message: "".to_string(),
                                };
                                if maybe_action.is_err() {
                                    login_info.message = "Invalid JSON".to_string();
                                } else {
                                    let maybe_login = maybe_action.unwrap();

                                    if let PlayerAction::Login(login) = maybe_login {
                                        if authenticated {
                                            log::info!("{} already authenticated, closing him.", id);
                                            let _ = websocket.close(None).await;
                                            continue;
                                        }
                                        let mut guard = instance.lock().await;

                                        info!("Login request for {}", login.nickname);
                                        let maybe_uuid = guard.authenticate(&login.nickname).await;
                                        if maybe_uuid.is_err() {
                                            login_info.message = format!("{}", maybe_uuid.err().unwrap());
                                            info!("Login error: {}", login_info.message);
                                            return Ok(())
                                        }

                                        let (player_id, infos_recv) = maybe_uuid.unwrap();

                                        id = player_id;


                                        info!("Login success for {}", id);
                                        authenticated = true;

                                        login_info.success = true;
                                        login_info.message = id.to_string();


                                        let maybe_login_info_str = serde_json::to_string(&login_info);
                                        assert!(maybe_login_info_str.is_ok());
                                        let result = websocket
                                            .send(Message::text(maybe_login_info_str.unwrap()))
                                            .await;
                                        if result.is_err() {
                                            info!("Message send error: {}", result.err().unwrap());
                                        }

                                        break infos_recv;

                                    } else {
                                        log::info!("Client not authenticated, closing him");
                                        let _ = websocket.close(None).await;
                                        return Ok(());
                                    }
                                }

                            }
                            Message::Binary(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Ping(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Pong(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Close(msg) => {
                                info!("WS close request received: {:?}", msg);
                                if id != Id::MAX {
                                    instance.lock().await.leave(id).await?;
                                } else {
                                    log::error!("Id is not assigned but closed received!");
                                }
                                return Ok(());
                            }
                            Message::Frame(msg) => {
                                log::info!("{:?}", msg);
                            }
                        }
                    }
                }
            };

            let mut stream = ReceiverStream::new(recv);

            loop {
                tokio::select! {
                    game_info = stream.next() => {
                        let str = serde_json::to_string(&game_info).unwrap();
                        let result = websocket.send(Message::text(str)).await;
                        if result.is_err() {
                            info!("Could not send data to client {}: {}", id, result.err().unwrap());
                            instance.lock().await.leave(id).await?;
                            let _ = websocket.close(None).await;
                            return Ok(());
                        }
                    },
                    Some(message) = websocket.next() => {
                        if message.is_err() {
                            info!("Websocket read error: {}", message.err().unwrap());
                            instance.lock().await.leave(id).await?;
                            return Ok(());
                        }
                        match message.unwrap() {
                            Message::Text(msg) => {
                                let maybe_action: serde_json::Result<PlayerAction> =
                                    serde_json::from_str(msg.as_str());

                                let mut login_info = AuthInfo {
                                    success: false,
                                    message: "".to_string(),
                                };
                                if maybe_action.is_err() {
                                    login_info.message = "Invalid JSON".to_string();
                                } else {
                                    let maybe_login = maybe_action.unwrap();

                                    if let PlayerAction::Login(_login) = maybe_login {
                                        if authenticated {
                                            log::info!("{} already authenticated, closing him.", id);
                                            let _ = websocket.close(None).await;
                                            return Ok(());
                                        }
                                    } else {
                                        let mut instance = instance.lock().await;
                                        let maybe_element = instance.borrow_galaxy_mut().borrow_body_mut(id);
                                        if let Some(maybe_player) = maybe_element {
                                            if let Entity::Player(player) =
                                                &mut maybe_player.entity
                                            {
                                                player.actions.push(maybe_login);
                                            }
                                        } else {
                                            error!("Can't find player {}", id);
                                        }
                                    }
                                }

                            }
                            Message::Binary(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Ping(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Pong(msg) => {
                                log::info!("{:?}", msg);
                            }
                            Message::Close(msg) => {
                                info!("WS close request received: {:?}", msg);
                                instance.lock().await.leave(id).await?;
                                return Ok(());
                            }
                            Message::Frame(msg) => {
                                log::info!("{:?}", msg);
                            }
                        }
                    }
                }
            }
        }
    }

    use crate::result::Result;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::RootCertStore;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::ServerName;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::TlsConnector;

    use crate::error::Error;

    pub enum ServerStream {
        Tls(tokio_rustls::server::TlsStream<TcpStream>),
        Tcp(TcpStream),
    }

    pub enum ClientStream {
        Tls(tokio_rustls::client::TlsStream<TcpStream>),
        Tcp(TcpStream),
    }

    pub enum ServerPki<'a> {
        Paths { key: String, cert: String },
        Slices { key: &'a [u8], cert: &'a [u8] },
        Rustls(rustls::ServerConfig),
    }

    #[derive(Clone)]
    pub enum ClientPki<'a> {
        WebPki,
        Path { cert: String },
        Slice { cert: &'a [u8] },
        Rustls(rustls::ClientConfig),
    }

    pub async fn connect(addr: &str, pki: Option<ClientPki<'_>>) -> Result<ClientStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|err| Error::TcpCouldNotConnect(err))?;

        if let None = pki {
            return Ok(ClientStream::Tcp(stream));
        }

        let tls_connector = get_connector(pki.unwrap())?;

        let stream = tls_connector
            .connect(
                ServerName::try_from("localhost").map_err(|err| Error::TlsHandshakeError(err))?,
                stream,
            )
            .await
            .map_err(|err| Error::CouldNotUpgradeToTls(err))?;
        return Ok(ClientStream::Tls(stream));
    }

    pub fn get_acceptor(pki: ServerPki) -> Result<TlsAcceptor> {
        match pki {
            ServerPki::Slices { key, cert } => {
                let cert = CertificateDer::from_pem_slice(cert)
                    .map_err(|err| Error::CertLoadError(err))?;
                let key = PrivatePkcs8KeyDer::from_pem_slice(key)
                    .map_err(|err| Error::KeyLoadError(err))?;

                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key))
                    .map_err(|err| Error::TlsConfigBuildError(err))?;
                Ok(TlsAcceptor::from(TlsAcceptor::from(Arc::new(config))))
            }
            ServerPki::Paths {
                key: key_path,
                cert: cert_path,
            } => {
                let cert = CertificateDer::from_pem_file(cert_path)
                    .map_err(|err| Error::CertLoadError(err))?;
                let key = PrivatePkcs8KeyDer::from_pem_file(key_path)
                    .map_err(|err| Error::KeyLoadError(err))?;

                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key))
                    .map_err(|err| Error::TlsConfigBuildError(err))?;
                Ok(TlsAcceptor::from(TlsAcceptor::from(Arc::new(config))))
            }
            ServerPki::Rustls(config) => Ok(TlsAcceptor::from(Arc::new(config))),
        }
    }

    pub fn get_connector(pki: ClientPki) -> Result<TlsConnector> {
        match pki {
            ClientPki::Slice { cert } => {
                let mut root_store = RootCertStore::empty();
                root_store.add_parsable_certificates(
                    CertificateDer::pem_slice_iter(cert).map(|result| result.unwrap()),
                );

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(root_store))
                    .with_no_client_auth();

                Ok(TlsConnector::from(Arc::new(config)))
            }
            ClientPki::Path { cert: cert_path } => {
                let mut root_store = RootCertStore::empty();
                root_store.add_parsable_certificates(
                    CertificateDer::pem_file_iter(cert_path)
                        .expect("Cannot open CA file")
                        .map(|result| result.unwrap()),
                );

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(root_store))
                    .with_no_client_auth();

                Ok(TlsConnector::from(Arc::new(config)))
            }
            ClientPki::WebPki => {
                let root_store = RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.into(),
                };

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(root_store))
                    .with_no_client_auth();

                Ok(TlsConnector::from(Arc::new(config)))
            }
            ClientPki::Rustls(config) => Ok(TlsConnector::from(Arc::new(config))),
        }
    }
}

mod server {
    pub enum TcpConfig {
        Port(u16),
        TcpListener(TcpListener),
    }

    pub struct ServerConfig<'a> {
        pub tcp: TcpConfig,
        pub pki: Option<ServerPki<'a>>,
    }

    fn poll_critical<T>(handlers: &mut T, cx: &mut Context<'_>) -> Result<()>
    where
        T: Stream<Item = std::result::Result<Result<()>, JoinError>> + Unpin + StreamExt,
    {
        while let Poll::Ready(Some(result)) = handlers.poll_next_unpin(cx) {
            if result.is_err() {
                return Err(Error::JoinError("".to_string()));
            }
        }
        Ok(())
    }

    pub async fn run(
        server_config: ServerConfig<'_>,
        stop: crossbeam::channel::Receiver<()>,
    ) -> Result<()> {
        let listener = match server_config.tcp {
            TcpConfig::Port(port) => TcpListener::bind(format!("localhost:{}", port))
                .await
                .map_err(|err| Error::TcpCouldNotConnect(err))?,
            TcpConfig::TcpListener(listener) => listener,
        };

        let tls_acceptor = if let Some(pki) = server_config.pki {
            Some(network::tls::get_acceptor(pki)?)
        } else {
            None
        };

        let mut ref_instant = tokio::time::Instant::now();
        let mut tls_handlers = FuturesUnordered::new();
        let mut http_handlers = FuturesUnordered::new();
        let mut ws_handlers = FuturesUnordered::new();
        let tick_value = std::time::Duration::from_millis(250);
        let mut update_tick_delay = tokio::time::interval(tick_value);
        let mut save_tick_delay = tokio::time::interval(std::time::Duration::from_secs(30));
        let mut http_hdl_recvs: Vec<Receiver<JoinHandle<Result<()>>>> = Vec::new();
        let mut ws_hdl_recvs: Vec<Receiver<JoinHandle<Result<()>>>> = Vec::new();

        info!(
            "Server loop starts, listenning on {}",
            listener.local_addr().unwrap().port()
        );

        // update_tick_delay.tick().await;
        save_tick_delay.tick().await;

        loop {
            tokio::select! {
                // ----------------------------------------------------
                // ON UPDATE TICK DELAY--------------------------------
                now = update_tick_delay.tick() => {

                    let mut must_stop = false;
                    if stop.try_recv().is_ok() {
                        log::info!("Stop signal received");
                        must_stop = true;
                    }

                    for hdl_recv in &http_hdl_recvs {
                        if let Ok(hdl) = hdl_recv.try_recv() {
                            http_handlers.push(hdl);
                        }
                    }


                    for hdl_recv in &ws_hdl_recvs {
                        if let Ok(hdl) = hdl_recv.try_recv() {
                            ws_handlers.push(hdl);
                        }
                    }

                    {
                        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                        poll_critical(&mut tls_handlers, &mut cx)?;
                        poll_critical(&mut http_handlers, &mut cx)?;
                        poll_critical(&mut ws_handlers, &mut cx)?;
                    }
                    let delta = now - ref_instant;
                    if delta > tick_value {
                        log::warn!("Server loop is too slow: {}s", delta.as_secs_f64());
                    }
                    ref_instant = now;
                    instance.lock().await.update(delta.as_secs_f64()).await;

                    if must_stop{
                        let save_result = instance.lock().await.save_all().await;
                        if save_result.is_err() {
                            log::error!("Failed to save instance properly: {}", save_result.err().unwrap());
                            return Err(Error::Error);
                        }
                        info!("Server loop stops now (on stop channel)!");
                        return Ok(())
                    }
                },
                // ----------------------------------------------------
                // ON SAVE TICK DELAY----------------------------------
                _ = save_tick_delay.tick() => {

                    let save_result = instance.lock().await.save_all().await;
                    if save_result.is_err() {
                        log::error!("Failed to save instance properly: {}", save_result.err().unwrap());
                    }
                },
                // ----------------------------------------------------
                // ON TCP ACCEPT---------------------------------------
                Ok((stream, addr)) = listener.accept() => {
                    info!("TCP accept from: {}", addr);

                    let cln = Arc::clone(&instance);
                    let (http_hdl_send, http_hdl_recv) = crossbeam::channel::bounded::<tokio::task::JoinHandle<Result<()>>>(1);
                    let (ws_hdl_send, ws_hdl_recv) = crossbeam::channel::bounded::<tokio::task::JoinHandle<Result<()>>>(1);
                    http_hdl_recvs.push(http_hdl_recv);
                    ws_hdl_recvs.push(ws_hdl_recv);
                    if let Some(tls_acceptor) = tls_acceptor.clone() {
                        let acceptor = tls_acceptor.clone();
                        let hdl = tokio::spawn(async move {
                            let tls_stream = acceptor.accept(stream).await.map_err(|_err| Error::Error)?;
                            http_hdl_send.send(run_http(tls_stream, cln, ws_hdl_send)).unwrap();
                            Ok(())
                        });
                        tls_handlers.push(hdl);
                    } else {
                        http_handlers.push(run_http(stream, Arc::clone(&instance), ws_hdl_send));
                    }
                },
            }
        }

        fn run_http<T>(
            stream: T,
            instance: Arc<Mutex<Instance>>,
            ws_hdl_sender: crossbeam::channel::Sender<tokio::task::JoinHandle<Result<()>>>,
        ) -> tokio::task::JoinHandle<Result<()>>
        where
            T: tokio::io::AsyncRead
                + tokio::io::AsyncWrite
                + std::marker::Unpin
                + std::marker::Send
                + 'static,
        {
            let io = TokioIo::new(stream);
            let hdl = tokio::task::spawn(async move {
                let instance = Arc::clone(&instance);

                http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let instance = Arc::clone(&instance);
                            let ws_hdl_sender = ws_hdl_sender.clone();
                            service::serve_http(req, instance, ws_hdl_sender)
                        }),
                    )
                    .with_upgrades()
                    .await
                    .map_err(|_err| Error::Error)?;
                Ok(())
            });
            hdl
        }
    }
}

#[cfg(test)]
mod tests_generate {
    use crate::world;

    #[test]
    fn case_01() {
        let chunk = world::generate_chunk();
    }
}
