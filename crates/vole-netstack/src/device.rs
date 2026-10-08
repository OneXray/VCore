use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

use crate::Packet;

/// A raw-IP device with one pending ingress and reserved bounded output slots.
pub(crate) struct RawIpDevice {
    rx: Option<Packet>,
    output: mpsc::Sender<Packet>,
    emitted: u64,
    capabilities: DeviceCapabilities,
}

impl RawIpDevice {
    pub(crate) fn new(mtu: usize, output: mpsc::Sender<Packet>) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = mtu;
        capabilities.medium = Medium::Ip;
        Self {
            rx: None,
            output,
            emitted: 0,
            capabilities,
        }
    }

    pub(crate) fn push_rx(&mut self, packet: Packet) -> Result<(), Packet> {
        if self.rx.is_some() {
            Err(packet)
        } else {
            self.rx = Some(packet);
            Ok(())
        }
    }

    pub(crate) fn rx_is_empty(&self) -> bool {
        self.rx.is_none()
    }

    pub(crate) fn pending_rx(&self) -> Option<&Packet> {
        self.rx.as_ref()
    }

    pub(crate) fn discard_rx(&mut self) {
        self.rx = None;
    }

    pub(crate) fn emitted(&self) -> u64 {
        self.emitted
    }

    pub(crate) fn tx_is_full(&self) -> bool {
        self.output.capacity() == 0
    }
}

impl Device for RawIpDevice {
    type RxToken<'a> = RawRxToken;
    type TxToken<'a> = RawTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve before consuming ingress: smoltcp can need an immediate
        // response, and concurrent generic UDP senders share this capacity.
        let permit = self.output.try_reserve().ok()?;
        let packet = self.rx.take()?;
        Some((
            RawRxToken(packet),
            RawTxToken {
                permit,
                emitted: &mut self.emitted,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(RawTxToken {
            permit: self.output.try_reserve().ok()?,
            emitted: &mut self.emitted,
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
    permit: mpsc::Permit<'a, Packet>,
    emitted: &'a mut u64,
}

impl TxToken for RawTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0_u8; len];
        let result = f(&mut bytes);
        self.permit.send(Packet::new(bytes));
        *self.emitted = self.emitted.wrapping_add(1);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_tx_queue_does_not_consume_rx() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output.clone());
        device.push_rx(Packet::new(vec![0x45; 40])).unwrap();
        output.try_send(Packet::new(vec![0x45; 40])).unwrap();

        assert!(device.receive(Instant::now()).is_none());
        assert!(!device.rx_is_empty());
        assert!(device.tx_is_full());
        receiver.try_recv().unwrap();
        let (rx, tx) = device.receive(Instant::now()).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[0x45; 40]));
        drop(tx);
        assert!(device.rx_is_empty());
        assert!(!device.tx_is_full());
    }

    #[test]
    fn unused_tx_permit_returns_capacity_without_a_packet() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output.clone());
        let token = device.transmit(Instant::now()).unwrap();
        assert_eq!(output.capacity(), 0);
        drop(token);
        assert_eq!(output.capacity(), 1);
        assert_eq!(device.emitted(), 0);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn consumed_tx_permit_sends_directly_to_the_only_output_queue() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(4, |bytes| bytes.copy_from_slice(&[0x45, 1, 2, 3]));
        assert_eq!(device.emitted(), 1);
        assert!(device.tx_is_full());
        assert_eq!(receiver.try_recv().unwrap().data(), &[0x45, 1, 2, 3]);
        assert!(!device.tx_is_full());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn one_pending_ingress_is_not_overwritten() {
        let (output, _receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device.push_rx(Packet::new(vec![0x45, 1])).unwrap();
        let rejected = device.push_rx(Packet::new(vec![0x45, 2])).unwrap_err();
        assert_eq!(rejected.data(), &[0x45, 2]);
        let (rx, tx) = device.receive(Instant::now()).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[0x45, 1]));
        drop(tx);
    }

    #[test]
    fn closed_output_never_consumes_pending_ingress() {
        let (output, receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device.push_rx(Packet::new(vec![0x45; 40])).unwrap();
        drop(receiver);
        assert!(device.receive(Instant::now()).is_none());
        assert!(device.transmit(Instant::now()).is_none());
        assert!(!device.rx_is_empty());
    }
}
