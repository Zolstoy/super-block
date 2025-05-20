use futures::SinkExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use log::info;
use std::sync::Arc;

use crate::network::websocket;

pub async fn service(
    mut request: Request<hyper::body::Incoming>,
    // instance: Arc<Mutex<Instance>>,
    // ws_hdl_sender: crossbeam::channel::Sender<tokio::task::JoinHandle<Result<()>>>,
) -> hyper::Result<Response<Full<Bytes>>> {
    let response_body = Full::<Bytes>::new("".into());
    let mut response = Response::<Full<Bytes>>::new(response_body);
    *response.status_mut() = StatusCode::BAD_REQUEST;

    if !hyper_tungstenite::is_upgrade_request(&request) {
        *response.body_mut() = Full::<Bytes>::new(format!("Websocket only").into());
        info!("HTTP non WS request");
        return Ok(response);
    }

    info!("Upgrade request");
    let res = hyper_tungstenite::upgrade(&mut request, None);
    if res.is_err() {
        let err_str: String = res.err().unwrap().to_string();

        *response.body_mut() =
            Full::<Bytes>::new(format!("Can't upgrade to websocket: {}", err_str).into());

        info!("WS upgrade error");
        return Ok(response);
    }

    let (ws_resp, websocket) = res.unwrap();

    let hdl = tokio::spawn(async move {
        // let instance_cln = Arc::clone(&instance);
        websocket::service(websocket).await?;
        Ok(())
    });

    Ok(ws_resp)
}
