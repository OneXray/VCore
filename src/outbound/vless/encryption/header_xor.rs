//! The random appearance retains header CTR even after Vision bypasses AEAD.
//! Preserve header/body progress across arbitrary read/write fragment sizes.
use super::crypto::Ctr;
use std::io;

#[derive(Default)]
pub(super) struct HeaderXor {
    header: [u8; 5],
    filled: usize,
    remaining: usize,
}

impl HeaderXor {
    pub(super) fn apply(
        &mut self,
        ctr: &mut Ctr,
        mut bytes: &mut [u8],
        decrypt: bool,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining != 0 {
                let count = self.remaining.min(bytes.len());
                self.remaining -= count;
                bytes = &mut bytes[count..];
                continue;
            }
            let count = (5 - self.filled).min(bytes.len());
            let (part, rest) = bytes.split_at_mut(count);
            if decrypt {
                ctr.apply(part)?;
            }
            self.header[self.filled..self.filled + count].copy_from_slice(part);
            if !decrypt {
                ctr.apply(part)?;
            }
            self.filled += count;
            bytes = rest;
            if self.filled == 5 {
                // Mihomo's XorConn ignores DecodeHeader's error, including
                // non-application TLS headers; these consume no body bytes.
                self.remaining = if self.header[..3] == [23, 3, 3] {
                    usize::from(u16::from_be_bytes([self.header[3], self.header[4]]))
                } else {
                    0
                };
                self.filled = 0;
            }
        }
        Ok(())
    }
}
