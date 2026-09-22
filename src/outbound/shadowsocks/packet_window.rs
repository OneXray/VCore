// SPDX-License-Identifier: MIT
//
// src/outbound/shadowsocks/packet_window.rs is derived from:
// https://github.com/shadowsocks/shadowsocks-rust/blob/ab388c7466d21f979430e33cc9ef10e22fb05955/crates/shadowsocks-service/src/net/packet_window.rs
//
// Upstream file attribution:
// Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
//
// shadowsocks-rust project attribution:
// Copyright (c) 2017 Y.T. CHUNG <zonyitoo@gmail.com>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Packet window
//!
//! Derived from shadowsocks-rust ab388c7466d21f979430e33cc9ef10e22fb05955,
//! crates/shadowsocks-service/src/net/packet_window.rs (MIT).
//! The upstream window algorithm is unchanged; the unused reset API is omitted.
//!
//! https://github.com/WireGuard/wireguard-go/blob/master/replay/replay.go

const BLOCK_BIT_LOG: u64 = 6; // 1<<6 == 64 bits
const BLOCK_BITS: u64 = 1 << BLOCK_BIT_LOG; // must be power of 2
const RING_BLOCKS: u64 = 1 << 7; // must be power of 2
const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS - 1;

/// Packet window for checking `packet_id` is in the sliding window
#[derive(Debug, Clone)]
pub struct PacketWindowFilter {
    last_packet_id: u64,
    packet_ring: [u64; RING_BLOCKS as usize],
}

impl Default for PacketWindowFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketWindowFilter {
    /// Create an empty filter
    pub fn new() -> Self {
        Self {
            last_packet_id: 0,
            packet_ring: [0u64; RING_BLOCKS as usize],
        }
    }

    /// Check and remember the `packet_id`
    ///
    /// Overlimit `packet_id >= limit` are always rejected
    pub fn validate_packet_id(&mut self, packet_id: u64, limit: u64) -> bool {
        if packet_id >= limit {
            return false;
        }

        let mut index_block = packet_id >> BLOCK_BIT_LOG;
        if packet_id > self.last_packet_id {
            // Move the window forward

            let current = self.last_packet_id >> BLOCK_BIT_LOG;
            let mut diff = index_block - current;
            if diff > RING_BLOCKS {
                // Clear the whole filter
                diff = RING_BLOCKS;
            }
            for d in 1..=diff {
                let i = current + d;
                self.packet_ring[(i & BLOCK_MASK) as usize] = 0;
            }
            self.last_packet_id = packet_id;
        } else if self.last_packet_id - packet_id > WINDOW_SIZE {
            // Behind the current window
            return false;
        }

        // Check and set bit
        index_block &= BLOCK_MASK;
        let index_bit = packet_id & BIT_MASK;
        let old = self.packet_ring[index_block as usize];
        let new = old | (1 << index_bit);
        self.packet_ring[index_block as usize] = new;
        old != new
    }
}
