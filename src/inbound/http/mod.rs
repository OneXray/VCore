#[cfg(feature = "inbound-http")]
mod framing;
mod parser;
#[cfg(feature = "inbound-http")]
mod server;

#[cfg(all(test, feature = "inbound-http"))]
mod tests;

pub(crate) use parser::read_request_head;
#[cfg(feature = "inbound-http")]
pub use server::{HttpBasicAuth, HttpServer, HttpServerConfig};
