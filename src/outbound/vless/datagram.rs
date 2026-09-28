//! Length-delimited VLESS UDP and packetaddr. XUDP uses the shared mux codec.
use super::{VlessCommand, outbound::PreparedStream};
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{
        DEFAULT_ESTABLISH_TIMEOUT,
        address::{decode_packet_addr, encode_packet_addr},
    },
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

pub(super) struct VlessDatagram {
    io: Option<BoxStream>,
    pending: Option<PreparedStream>,
    packet_addr: bool,
    peer: Option<Destination>,
    initialized: bool,
    deadline: Instant,
    resolution: ResolutionContext,
    budget: DatagramBudget,
    input: BytesMut,
    cancellation: tokio_util::sync::CancellationToken,
}

impl VlessDatagram {
    pub(super) fn new(
        prepared: PreparedStream,
        packet_addr: bool,
        budget: DatagramBudget,
        resolution: ResolutionContext,
    ) -> Self {
        let deadline = prepared.deadline;
        let cancellation = prepared.token.clone();
        Self {
            io: None,
            pending: Some(prepared),
            packet_addr,
            peer: None,
            initialized: false,
            deadline,
            resolution,
            budget,
            input: BytesMut::new(),
            cancellation,
        }
    }
    async fn fill(&mut self, required: usize) -> io::Result<()> {
        if required > crate::limits::VLESS_UDP_FRAME_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut scratch = [0; 1024];
        while self.input.len() < required {
            let size = (required - self.input.len()).min(scratch.len());
            let count = self
                .io
                .as_mut()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .read(&mut scratch[..size])
                .await?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.input.extend_from_slice(&scratch[..count]);
        }
        Ok(())
    }
    async fn next(&mut self) -> io::Result<(Destination, Bytes)> {
        self.fill(2).await?;
        let length = u16::from_be_bytes(self.input[..2].try_into().unwrap()) as usize;
        if length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.fill(length + 2).await?;
        let packet = self.input.split().freeze().slice(2..);
        let (peer, start) = if self.packet_addr {
            decode_packet_addr(&packet)?
        } else {
            (self.peer.clone().ok_or(io::ErrorKind::InvalidData)?, 0)
        };
        if start == packet.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok((peer, packet.slice(start..)))
    }
}

#[async_trait]
impl DatagramTransport for VlessDatagram {
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let overhead = if !self.packet_addr {
            0
        } else if matches!(peer,Destination::Ip(addr) if addr.is_ipv4()) {
            7
        } else {
            19
        };
        let max = u16::MAX - overhead;
        self.budget.intersect(DatagramBudget::new(max, max))
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if self.cancellation.is_cancelled() {
            self.close().await?;
            return Err(DispatchError::NotAllowed);
        }
        if self.io.is_none() && self.pending.is_none() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        if packet.payload.is_empty()
            || packet.remote.port() == 0
            || packet.payload.len() > self.payload_budget(&packet.remote).transmit() as usize
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        if !self.packet_addr
            && self
                .peer
                .as_ref()
                .is_some_and(|peer| *peer != packet.remote)
        {
            return Err(DispatchError::NotAllowed);
        }
        let first = !self.initialized;
        if first && Instant::now() >= self.deadline {
            self.io.take();
            self.pending.take();
            return Err(DispatchError::TimedOut);
        }
        let mut wire = BytesMut::with_capacity(packet.payload.len() + 21);
        wire.put_u16(0);
        if self.packet_addr {
            let deadline = if first {
                self.deadline
            } else {
                Instant::now() + DEFAULT_ESTABLISH_TIMEOUT
            };
            let peer = tokio::select! {
                biased;
                () = self.cancellation.cancelled() => {
                    self.close().await?;
                    return Err(DispatchError::NotAllowed);
                }
                result = self.resolution.resolve_ip(&packet.remote, deadline) => result?,
            };
            encode_packet_addr(&peer.into(), &mut wire)?;
        }
        wire.extend_from_slice(&packet.payload);
        let length = (wire.len() - 2) as u16;
        wire[..2].copy_from_slice(&length.to_be_bytes());
        let mut stream = if let Some(prepared) = self.pending.take() {
            let destination = if self.packet_addr {
                Destination::domain("sp.packet-addr.v2fly.arpa", 443)?
            } else {
                packet.remote.clone()
            };
            prepared
                .finish(VlessCommand::Udp, Some(&destination))
                .await?
        } else {
            self.io
                .take()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
        };
        let write = async {
            stream.write_all(&wire).await?;
            stream.flush().await
        };
        if first {
            tokio::time::timeout_at(self.deadline, write)
                .await
                .map_err(|_| DispatchError::TimedOut)??;
        } else {
            write.await?;
        }
        self.peer.get_or_insert(packet.remote);
        self.initialized = true;
        self.io = Some(stream);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.io.is_none() && self.pending.is_none() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        if !self.initialized {
            self.cancellation.cancelled().await;
            self.close().await?;
            return Err(DispatchError::NotAllowed);
        }
        let mut count = 0;
        loop {
            let (remote, payload) = match self.next().await {
                Ok(packet) => packet,
                Err(error) => {
                    self.io.take();
                    return Err(error.into());
                }
            };
            if payload.len() <= self.payload_budget(&remote).receive() as usize {
                return Ok(Datagram {
                    remote,
                    payload,
                    sniffed_domain: None,
                });
            }
            count += 1;
            if count == crate::limits::IO_POLL_BUDGET {
                tokio::task::yield_now().await;
                count = 0;
            }
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.io.take();
        self.pending.take();
        self.input.clear();
        Ok(())
    }
}
