use std::collections::VecDeque;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};

use crate::Packet;

/// A raw-IP smoltcp device with fixed-depth ingress and egress queues.
pub(crate) struct RawIpDevice {
    rx: VecDeque<Packet>,
    tx: VecDeque<Packet>,
    queue_limit: usize,
    capabilities: DeviceCapabilities,
}

impl RawIpDevice {
    pub(crate) fn new(mtu: usize, queue_limit: usize) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = mtu;
        capabilities.medium = Medium::Ip;
        Self {
            rx: VecDeque::with_capacity(queue_limit),
            tx: VecDeque::with_capacity(queue_limit),
            queue_limit,
            capabilities,
        }
    }

    pub(crate) fn push_rx(&mut self, packet: Packet) -> Result<(), Packet> {
        if self.rx.len() == self.queue_limit {
            Err(packet)
        } else {
            self.rx.push_back(packet);
            Ok(())
        }
    }

    pub(crate) fn pop_tx(&mut self) -> Option<Packet> {
        self.tx.pop_front()
    }

    pub(crate) fn push_tx_front(&mut self, packet: Packet) {
        debug_assert!(self.tx.len() < self.queue_limit);
        self.tx.push_front(packet);
    }

    pub(crate) fn tx_is_full(&self) -> bool {
        self.tx.len() == self.queue_limit
    }

    #[cfg(test)]
    pub(crate) fn queue_lengths(&self) -> (usize, usize) {
        (self.rx.len(), self.tx.len())
    }
}

impl Device for RawIpDevice {
    type RxToken<'a> = RawRxToken;
    type TxToken<'a> = RawTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx.len() == self.queue_limit {
            return None;
        }
        let packet = self.rx.pop_front()?;
        Some((
            RawRxToken(packet),
            RawTxToken {
                queue: &mut self.tx,
                queue_limit: self.queue_limit,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.tx.len() < self.queue_limit).then_some(RawTxToken {
            queue: &mut self.tx,
            queue_limit: self.queue_limit,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub(crate) struct RawRxToken(Packet);

impl RxToken for RawRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0.data())
    }
}

pub(crate) struct RawTxToken<'a> {
    queue: &'a mut VecDeque<Packet>,
    queue_limit: usize,
}

impl TxToken for RawTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        debug_assert!(self.queue.len() < self.queue_limit);
        let mut bytes = vec![0_u8; len];
        let result = f(&mut bytes);
        self.queue.push_back(Packet::new(bytes));
        result
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::Device as _;

    use super::*;

    #[test]
    fn full_tx_queue_does_not_consume_rx() {
        let mut device = RawIpDevice::new(1_500, 1);
        device.push_rx(Packet::new(vec![0x45; 40])).unwrap();
        device.tx.push_back(Packet::new(vec![0x45; 40]));

        assert!(device.receive(Instant::now()).is_none());
        assert_eq!(device.queue_lengths(), (1, 1));
    }
}
