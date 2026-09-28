//! HTTP/3 over the shared controlled datagram seam. No socket or DNS fallback.
use super::{ConnectionGuard, DriverOwner, SendRequest, connection_closed};
use crate::{
    dispatch::{DatagramBudget, DatagramTransport},
    transport::quic,
};
use bytes::Bytes;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

pub(crate) struct QuicTransport {
    pub transport: Box<dyn DatagramTransport>,
    pub peer: SocketAddr,
    pub budget: DatagramBudget,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
}

#[derive(Clone)]
pub(super) struct Sender {
    pub requests: h3::client::SendRequest<super::h3_upload::OpenStreams, Bytes>,
    pub runtime: Arc<OwnedRuntime>,
    #[cfg(feature = "interop-test")]
    pub observation: quinn::Connection,
}
impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Sender").finish_non_exhaustive()
    }
}

use crate::transport::quic::OwnedRuntime;

pub(super) async fn connect(
    raw: QuicTransport,
    keepalive: i32,
    owner: &DriverOwner,
) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
    let cancel = owner.cancellation.child_token();
    let stop = cancel.clone();
    let (ready, response) = oneshot::channel();
    let guard = owner.spawn_managed(
        async move {
            // Keep QUIC alive for the bounded close exchange after logical
            // cancellation. Cancelling its runtime first loses CONNECTION_CLOSE.
            let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
            let mut ready = Some(ready);
            let mut driver = None;
            let mut endpoint = None;
            let connection = async {
                let crypto =
                    quinn::crypto::rustls::QuicClientConfig::try_from(raw.tls).map_err(failure)?;
                let (socket, datagram) = quic::attach(raw.transport, raw.peer, raw.budget)?;
                driver = Some(datagram);
                let mtu = socket.budget().quic_payload_limit()?;
                let mut limits = quinn::TransportConfig::default();
                limits
                    .initial_mtu(mtu)
                    .min_mtu(mtu)
                    .mtu_discovery_config(None)
                    .max_concurrent_bidi_streams(0_u8.into())
                    .max_concurrent_uni_streams((crate::limits::XHTTP_H3_UNI_STREAMS as u32).into())
                    .stream_receive_window((crate::limits::XHTTP_H3_STREAM_WINDOW as u32).into())
                    .receive_window((crate::limits::XHTTP_H3_CONNECTION_WINDOW as u32).into())
                    .send_window(crate::limits::XHTTP_H3_SEND_WINDOW as u64)
                    .datagram_receive_buffer_size(None)
                    .datagram_send_buffer_size(0)
                    .max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(failure)?))
                    .keep_alive_interval((keepalive >= 0).then(|| {
                        Duration::from_secs(if keepalive == 0 { 10 } else { keepalive as u64 })
                    }));
                let mut client = quinn::ClientConfig::new(Arc::new(crypto));
                client.transport_config(Arc::new(limits));
                let mut config = quinn::EndpointConfig::default();
                config.max_udp_payload_size(mtu).map_err(failure)?;
                let mut peer = quinn::Endpoint::new_with_abstract_socket(
                    config,
                    None,
                    socket,
                    runtime.clone(),
                )?;
                peer.set_default_client_config(client);
                endpoint = Some(peer);
                let connected = endpoint
                    .as_ref()
                    .unwrap()
                    .connect(raw.peer, &raw.server_name)
                    .map_err(failure)?
                    .await
                    .map_err(failure)?;
                let (mut control, requests) = h3::client::builder()
                    .max_field_section_size(u64::from(super::MAX_H2_HEADER_LIST_SIZE))
                    .build(super::h3_upload::Connection::new(connected.clone()))
                    .await
                    .map_err(failure)?;
                // h3 closes the connection when its last request sender is dropped,
                // even while response/upload streams still exist. Keep one sender
                // with the physical driver, whose lease owns the connection lifetime.
                let keep_requests = requests.clone();
                ready
                    .take()
                    .unwrap()
                    .send(Ok(Sender {
                        requests,
                        runtime: runtime.clone(),
                        #[cfg(feature = "interop-test")]
                        observation: connected,
                    }))
                    .map_err(|_| connection_closed())?;
                let _ = control.wait_idle().await;
                drop(keep_requests);
                Ok::<_, io::Error>(())
            };
            let result = tokio::select! {biased;
                () = stop.cancelled() => Err(connection_closed()),
                result = connection => result,
            };
            if let Some(ready) = ready {
                let _ = ready.send(Err(result.err().unwrap_or_else(connection_closed)));
            }
            if let Some(endpoint) = endpoint {
                endpoint.close(0_u8.into(), b"");
                let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, endpoint.wait_idle()).await;
            }
            runtime.stop().await;
            if let Some(driver) = driver {
                let _ = driver.stop().await;
            }
        },
        cancel,
    )?;
    let sender = response.await.map_err(|_| connection_closed())??;
    Ok((SendRequest::H3(sender), Arc::new(guard)))
}

pub(super) fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("XHTTP HTTP/3 exchange failed")
}
