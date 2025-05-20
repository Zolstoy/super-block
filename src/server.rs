use crate::error::Error;
use crate::network;
use crate::network::http;
use crate::network::ServerPki;
use crate::Result;
use crossbeam::channel::Receiver;
use futures::stream::FuturesUnordered;
use futures::Stream;
use futures::StreamExt;
use hyper::server::conn::http1::{self};
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use log::info;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tokio::net::TcpListener;
use tokio::sync::futures;
use tokio::sync::Mutex;
use tokio::task::JoinError;
use tokio::task::JoinHandle;

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
        Some(network::get_acceptor(pki)?)
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
