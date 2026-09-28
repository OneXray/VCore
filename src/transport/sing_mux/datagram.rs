//! Address-per-packet sing-mux UDP. Partial reads survive cancellation; a
//! partially sent frame poisons this logical stream, never its siblings.
use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::BytesMut;
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(crate) struct DatagramIo {
    io: Option<BoxStream>,
    input: BytesMut,
    budget: DatagramBudget,
    resolution: ResolutionContext,
    deadline: Instant,
    first: bool,
    cancel: CancellationToken,
}
impl DatagramIo {
    pub(crate) fn new(
        io: BoxStream,
        budget: DatagramBudget,
        resolution: ResolutionContext,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            io: Some(io),
            input: BytesMut::new(),
            budget,
            resolution,
            deadline,
            first: true,
            cancel,
        }
    }
    async fn fill(&mut self, length: usize) -> io::Result<()> {
        if length > u16::MAX as usize + 261 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut scratch = [0; 1024];
        while self.input.len() < length {
            let count = (length - self.input.len()).min(scratch.len());
            let n = self
                .io
                .as_mut()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .read(&mut scratch[..count])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.input.extend_from_slice(&scratch[..n]);
        }
        Ok(())
    }
    async fn next(&mut self) -> io::Result<Datagram> {
        self.fill(2).await?;
        let address_len = match self.input[0] {
            1 => 7,
            4 => 19,
            3 => self.input[1] as usize + 4,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        self.fill(address_len + 2).await?;
        let (remote, _) = crate::socks5::decode_address(&self.input[..address_len])
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let length =
            u16::from_be_bytes(self.input[address_len..address_len + 2].try_into().unwrap())
                as usize;
        if length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.fill(address_len + 2 + length).await?;
        let payload = self.input.split().freeze().slice(address_len + 2..);
        Ok(Datagram {
            remote,
            payload,
            sniffed_domain: None,
        })
    }
}
#[async_trait]
impl DatagramTransport for DatagramIo {
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if packet.remote.port() == 0
            || packet.payload.is_empty()
            || packet.payload.len() > self.budget.transmit() as usize
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let deadline = if self.first {
            self.deadline
        } else {
            Instant::now() + crate::outbound::DEFAULT_ESTABLISH_TIMEOUT
        };
        let peer = tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            peer=self.resolution.resolve_ip(&packet.remote,deadline)=>peer?,
        };
        let mut wire = Vec::with_capacity(packet.payload.len() + 21);
        crate::socks5::encode_address(&peer.into(), &mut wire)?;
        wire.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&packet.payload);
        let mut io = self
            .io
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            result=async {
                let write=async {io.write_all(&wire).await?;io.flush().await};
                if self.first {tokio::time::timeout_at(deadline,write).await.map_err(|_|io::ErrorKind::TimedOut)?} else {write.await}
            }=>result?,
        }
        self.first = false;
        self.io = Some(io);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let cancel = self.cancel.clone();
        for count in 0_usize.. {
            let result = tokio::select! {biased;
                ()=cancel.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
                result=self.next()=>result,
            };
            match result {
                Ok(packet) if packet.payload.len() <= self.budget.receive() as usize => {
                    return Ok(packet);
                }
                Ok(_) => {}
                Err(error) => {
                    self.close().await?;
                    return Err(error.into());
                }
            }
            if count % crate::limits::IO_POLL_BUDGET == crate::limits::IO_POLL_BUDGET - 1 {
                tokio::task::yield_now().await;
            }
        }
        unreachable!()
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.io.take();
        self.input.clear();
        Ok(())
    }
}
