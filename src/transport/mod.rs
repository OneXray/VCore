//! Outbound wire transports.

#[cfg(feature = "outbound-vless")]
pub mod xhttp;

pub const STREAM_CHUNK_BYTES: usize = 16 * 1024;
pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(feature = "stream-transport")]
mod ws;
#[cfg(feature = "stream-transport")]
pub use ws::{
    MAX_EARLY_DATA_BYTES, WebSocketEarlyData, WebSocketOptions, connect_websocket, websocket,
};

#[cfg(feature = "stream-transport")]
mod http_head;
#[cfg(feature = "stream-transport")]
pub use http_head::{HTTP_HEAD_BYTES, HTTP_HEADER_COUNT};

#[cfg(feature = "stream-transport")]
mod grpc;
#[cfg(feature = "stream-transport")]
pub use grpc::{Driver as StreamDriver, grpc, legacy_h2};

#[cfg(feature = "stream-transport")]
mod http_obfs;
#[cfg(feature = "stream-transport")]
pub use http_obfs::{HttpObfsOptions, http_obfs};
#[cfg(feature = "quic-transport")]
pub mod quic;
