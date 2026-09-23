use std::io;

use super::{DatagramTransport, DispatchError};
use crate::packet::IpVersion;
use crate::session::{Datagram, Destination};

pub const QUIC_MIN_PAYLOAD_BYTES: u16 = 1200;
pub const WIREGUARD_MIN_INNER_MTU: u16 = 1280;
pub const WIREGUARD_TRANSPORT_OVERHEAD: u16 = 32;

/// Directional payload ceilings at one datagram seam, excluding its envelope.
/// Zero means no nonempty payload fits, not permission to remove a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramBudget {
    transmit: u16,
    receive: u16,
}

impl DatagramBudget {
    pub const fn new(transmit: u16, receive: u16) -> Self {
        Self { transmit, receive }
    }
    pub const fn transmit(self) -> u16 {
        self.transmit
    }
    pub const fn receive(self) -> u16 {
        self.receive
    }

    pub fn from_path_mtu(mtu: u16, version: IpVersion) -> io::Result<Self> {
        let overhead = match version {
            IpVersion::V4 => 28,
            IpVersion::V6 => 48,
        };
        let payload = mtu
            .checked_sub(overhead)
            .filter(|value| *value > 0)
            .ok_or_else(invalid)?;
        Ok(Self::new(payload, payload))
    }

    pub fn intersect(self, other: Self) -> Self {
        Self::new(
            self.transmit.min(other.transmit),
            self.receive.min(other.receive),
        )
    }

    pub fn subtract_overhead(self, transmit: usize, receive: usize) -> Self {
        Self::new(
            usize::from(self.transmit).saturating_sub(transmit) as u16,
            usize::from(self.receive).saturating_sub(receive) as u16,
        )
    }

    pub fn quic_payload_limit(self) -> io::Result<u16> {
        let payload = self.transmit.min(self.receive);
        if payload < QUIC_MIN_PAYLOAD_BYTES {
            return Err(invalid());
        }
        Ok(payload)
    }

    /// WireGuard transport data is padded to a 16-byte boundary. Handshake
    /// packets (148/92 bytes) also fit whenever the 1280-byte inner MTU fits.
    pub fn wireguard_inner_mtu(self, requested: u16) -> io::Result<u16> {
        let available = self
            .transmit
            .min(self.receive)
            .saturating_sub(WIREGUARD_TRANSPORT_OVERHEAD)
            / 16
            * 16;
        let mtu = available.min(requested);
        if mtu < WIREGUARD_MIN_INNER_MTU {
            return Err(invalid());
        }
        Ok(mtu)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "datagram path budget is insufficient",
    )
}

/// Enforce the caller's limit outside a codec, and retain all lower-layer caps.
pub(crate) fn bounded(
    inner: Box<dyn DatagramTransport>,
    budget: DatagramBudget,
) -> Box<dyn DatagramTransport> {
    Box::new(Bounded {
        inner,
        budget,
        closing: false,
        closed: false,
        observation: Some(crate::resources::observation::track(
            crate::resources::observation::ResourceKind::Association,
        )),
    })
}

struct Bounded {
    inner: Box<dyn DatagramTransport>,
    budget: DatagramBudget,
    closing: bool,
    closed: bool,
    observation: Option<crate::resources::observation::Guard>,
}

#[async_trait::async_trait]
impl DatagramTransport for Bounded {
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.budget.intersect(self.inner.payload_budget(peer))
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closing {
            return Err(DispatchError::NotAllowed);
        }
        if datagram.payload.len() > usize::from(self.payload_budget(&datagram.remote).transmit()) {
            return Err(invalid().into());
        }
        self.inner.send(datagram).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closing {
            return Err(DispatchError::NotAllowed);
        }
        loop {
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                let datagram = self.inner.receive().await?;
                if datagram.payload.len()
                    <= usize::from(self.payload_budget(&datagram.remote).receive())
                {
                    return Ok(datagram);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed {
            return Ok(());
        }
        self.closing = true;
        self.inner.close().await?;
        self.closed = true;
        self.observation.take();
        Ok(())
    }
}
