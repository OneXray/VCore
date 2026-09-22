use bytes::Bytes;

/// One raw IPv4 or IPv6 packet, without a platform-specific TUN prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet(Bytes);

impl Packet {
    #[must_use]
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self(data.into())
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl<T> From<T> for Packet
where
    T: Into<Bytes>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
