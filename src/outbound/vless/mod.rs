//! VLESS framing and connector assembly over shared stream transports.
mod codec;
mod datagram;
// The native wire seam is exercised before admitting public YAML or runtime wiring.
#[cfg(any(test, feature = "interop-test"))]
#[doc(hidden)]
pub mod encryption;
mod outbound;
mod vision;
mod vision_filter;
pub use codec::{VlessCommand, VlessStream, encode_request_header, read_response_header};
pub use outbound::VlessOutbound;
pub(crate) use outbound::VlessResourceLimits;
