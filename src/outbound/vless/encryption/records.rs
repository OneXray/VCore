use super::cache::{Cache, Ticket};
use super::crypto::{Aead, Ctr, Suite, failure};
use crate::dispatch::BoxStream;
use std::sync::Arc;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Records {
    raw: Option<BoxStream>,
    key: Zeroizing<[u8; 96]>,
    suite: Suite,
    tx: Aead,
    rx: Option<Aead>,
    tx_ctr: Option<Ctr>,
    rx_ctr: Option<Ctr>,
    pending: Vec<u8>,
    sent: usize,
    input: Vec<u8>,
    filled: usize,
    reading: Reading,
    plain: Zeroizing<Vec<u8>>,
    consumed: usize,
    write_closed: bool,
    cache: Arc<Cache>,
    ticket: Option<Arc<Ticket>>,
    random_headers: bool,
}

enum Reading {
    Random,
    Padding,
    Header,
    Body([u8; 5]),
    Eof,
}

impl Records {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        raw: BoxStream,
        key: Zeroizing<[u8; 96]>,
        suite: Suite,
        tx: Aead,
        rx: Aead,
        tx_ctr: Option<Ctr>,
        rx_ctr: Option<Ctr>,
        padding: usize,
        cache: Arc<Cache>,
        ticket: Option<Arc<Ticket>>,
    ) -> Self {
        Self {
            raw: Some(raw),
            key,
            suite,
            tx,
            rx: Some(rx),
            tx_ctr,
            rx_ctr,
            pending: Vec::new(),
            sent: 0,
            input: vec![0; padding],
            filled: 0,
            reading: Reading::Padding,
            plain: Zeroizing::new(Vec::new()),
            consumed: 0,
            write_closed: false,
            cache,
            ticket,
            random_headers: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resumed(
        raw: BoxStream,
        key: Zeroizing<[u8; 96]>,
        suite: Suite,
        tx: Aead,
        tx_ctr: Option<Ctr>,
        random_headers: bool,
        prefix: Vec<u8>,
        cache: Arc<Cache>,
        ticket: Arc<Ticket>,
    ) -> Self {
        Self {
            raw: Some(raw),
            key,
            suite,
            tx,
            rx: None,
            tx_ctr,
            rx_ctr: None,
            pending: prefix,
            sent: 0,
            input: vec![0; 16],
            filled: 0,
            reading: Reading::Random,
            plain: Zeroizing::new(Vec::new()),
            consumed: 0,
            write_closed: false,
            cache,
            ticket: Some(ticket),
            random_headers,
        }
    }

    fn open(&self) -> io::Result<()> {
        if self.cache.cancellation.is_cancelled() {
            return Err(super::cache::closed());
        }
        if self.raw.is_none() {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "VLESS Encryption stream closed",
            ))
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        if let Some(ticket) = self.ticket.take() {
            self.cache.invalidate(&ticket);
        }
        self.raw.take();
        self.key.zeroize();
        self.plain.zeroize();
        self.pending.clear();
        self.input.clear();
        error
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.open() {
            return Poll::Ready(Err(self.fail(error)));
        }
        while self.sent < self.pending.len() {
            let result = ready!(
                Pin::new(self.raw.as_mut().unwrap()).poll_write(cx, &self.pending[self.sent..])
            );
            let count = match result {
                Ok(0) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VLESS Encryption transport closed",
                    ))));
                }
                Ok(count) => count,
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            };
            self.sent += count;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn receive(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.open()?;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        ready!(self.drain(cx))?;
        loop {
            if self.consumed < self.plain.len() {
                let count = output.remaining().min(self.plain.len() - self.consumed);
                output.put_slice(&self.plain[self.consumed..self.consumed + count]);
                self.consumed += count;
                return Poll::Ready(Ok(()));
            }
            self.plain.zeroize();
            self.plain.clear();
            self.consumed = 0;
            if matches!(self.reading, Reading::Eof) {
                return Poll::Ready(Ok(()));
            }
            while self.filled < self.input.len() {
                let mut buf = ReadBuf::new(&mut self.input[self.filled..]);
                ready!(Pin::new(self.raw.as_mut().unwrap()).poll_read(cx, &mut buf))?;
                let count = buf.filled().len();
                if count == 0 {
                    if self.filled == 0 && matches!(self.reading, Reading::Header) {
                        self.reading = Reading::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VLESS Encryption record",
                    )));
                }
                self.filled += count;
            }
            match self.reading {
                Reading::Random => {
                    self.rx = Some(Aead::new(&self.input, self.key.as_ref(), self.suite)?);
                    if self.random_headers {
                        self.rx_ctr = Some(Ctr::new(
                            self.key.as_ref(),
                            self.input.as_slice().try_into().map_err(|_| failure())?,
                        )?);
                    }
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Padding => {
                    let _padding =
                        Zeroizing::new(self.rx.as_mut().unwrap().open(&self.input, &[], None)?);
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Header => {
                    if let Some(ctr) = self.rx_ctr.as_mut() {
                        ctr.apply(&mut self.input)?;
                    }
                    let header: [u8; 5] =
                        self.input.as_slice().try_into().map_err(|_| failure())?;
                    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                    if header[..3] != [23, 3, 3] || !(17..=17000).contains(&length) {
                        return Poll::Ready(Err(failure()));
                    }
                    self.reading = Reading::Body(header);
                    self.input.resize(length, 0);
                }
                Reading::Body(header) => {
                    let rx = self.rx.as_mut().unwrap();
                    let rekey = rx.exhausted();
                    self.plain = Zeroizing::new(rx.open(&self.input, &header, None)?);
                    if rekey {
                        let mut context = header.to_vec();
                        context.extend_from_slice(&self.input);
                        self.rx = Some(Aead::new(&context, self.key.as_ref(), self.suite)?);
                    }
                    self.ticket.take();
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Eof => unreachable!(),
            }
            self.filled = 0;
        }
    }
}

impl AsyncRead for Records {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.receive(cx, output) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            result => result,
        }
    }
}

impl AsyncWrite for Records {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VLESS Encryption write side closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(8192);
        let length = (count + 16) as u16;
        let mut header = [23, 3, 3, (length >> 8) as u8, length as u8];
        let rekey = self.tx.exhausted();
        let result = (|| {
            let sealed = self.tx.seal(&input[..count], &header, None)?;
            if rekey {
                let mut context = header.to_vec();
                context.extend_from_slice(&sealed);
                self.tx = Aead::new(&context, self.key.as_ref(), self.suite)?;
            }
            if let Some(ctr) = self.tx_ctr.as_mut() {
                ctr.apply(&mut header)?;
            }
            self.pending.extend_from_slice(&header);
            self.pending.extend_from_slice(&sealed);
            Ok(count)
        })();
        Poll::Ready(result.map_err(|error| self.fail(error)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        match Pin::new(self.raw.as_mut().unwrap()).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            result => result,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        match Pin::new(self.raw.as_mut().unwrap()).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct Fragmented {
        input: Vec<u8>,
        read: usize,
        output: Arc<Mutex<Vec<u8>>>,
        pending: bool,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for Fragmented {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    impl Fragmented {
        fn yield_once(&mut self, cx: &mut Context<'_>) -> bool {
            self.pending = !self.pending;
            if self.pending {
                cx.waker().wake_by_ref();
            }
            self.pending
        }
    }
    impl AsyncRead for Fragmented {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.yield_once(cx) {
                return Poll::Pending;
            }
            if self.read < self.input.len() && b.remaining() != 0 {
                b.put_slice(&self.input[self.read..self.read + 1]);
                self.read += 1;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Fragmented {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.yield_once(cx) {
                return Poll::Pending;
            }
            let count = b.len().min(1);
            self.output.lock().unwrap().extend_from_slice(&b[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        v.as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../tests/protocols/encryption-crypto.json"
        ))
        .unwrap()
    }
    fn wire(v: &serde_json::Value) -> Vec<u8> {
        [bytes(&v["aad"]), bytes(&v["ciphertext"])].concat()
    }
    fn fixture(
        v: &serde_json::Value,
        input: Vec<u8>,
        output: Arc<Mutex<Vec<u8>>>,
        dropped: Arc<AtomicBool>,
    ) -> Records {
        let key: [u8; 96] = bytes(&v["key"]).try_into().unwrap();
        let suite = if v["cipher"] == "aes256gcm" {
            Suite::Aes
        } else {
            Suite::ChaCha
        };
        Records::resumed(
            Box::new(Fragmented {
                input,
                read: 0,
                output,
                pending: false,
                dropped,
            }),
            Zeroizing::new(key),
            suite,
            Aead::new(&bytes(&v["context"]), &key, suite).unwrap(),
            None,
            false,
            Vec::new(),
            Arc::new(Cache::default()),
            Arc::new(Ticket {
                pfs: Zeroizing::new([0; 64]),
                bytes: Zeroizing::new([0; 16]),
                expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            }),
        )
    }

    #[tokio::test]
    async fn fragmented_io_and_cancelled_reads_preserve_independent_go_records() {
        for records in vectors()["records"].as_array().unwrap().chunks_exact(3) {
            let v = &records[0];
            let expected = [wire(v), wire(&records[1])].concat();
            let input = [bytes(&v["context"]), expected.clone()].concat();
            let output = Arc::new(Mutex::new(Vec::new()));
            let mut stream = fixture(v, input, output.clone(), Arc::default());
            let payload = bytes(&v["plaintext"]);
            for _ in 0..2 {
                stream.write_all(&payload).await.unwrap();
            }
            stream.flush().await.unwrap();
            assert_eq!(
                *output.lock().unwrap(),
                expected,
                "partial writes must not reseal or reuse a nonce"
            );
            let mut buffer = [0; 1];
            let mut cx = Context::from_waker(std::task::Waker::noop());
            for _ in 0..23 {
                let mut read = ReadBuf::new(&mut buffer);
                assert!(
                    Pin::new(&mut stream)
                        .poll_read(&mut cx, &mut read)
                        .is_pending()
                );
                assert!(
                    read.filled().is_empty(),
                    "unauthenticated fragments must stay private"
                );
            }
            let mut actual = Vec::new();
            stream.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, payload.repeat(2));
        }
    }

    #[tokio::test]
    async fn corrupt_truncated_or_replayed_records_fail_closed_without_plaintext() {
        for records in vectors()["records"].as_array().unwrap().chunks_exact(3) {
            let v = &records[0];
            let good = wire(v);
            let variants = [
                {
                    let mut data = good.clone();
                    data[0] = 22;
                    data
                },
                {
                    let mut data = good.clone();
                    data[3..5].copy_from_slice(&17001u16.to_be_bytes());
                    data
                },
                {
                    let mut data = good.clone();
                    *data.last_mut().unwrap() ^= 1;
                    data
                },
                good[..4].to_vec(),
                good[..good.len() - 1].to_vec(),
                wire(&records[1]),
            ];
            for bad in variants {
                let dropped = Arc::new(AtomicBool::new(false));
                let mut stream = fixture(
                    v,
                    [bytes(&v["context"]), bad].concat(),
                    Arc::default(),
                    dropped.clone(),
                );
                let mut actual = Vec::new();
                assert!(stream.read_to_end(&mut actual).await.is_err());
                assert!(actual.is_empty());
                assert!(dropped.load(Ordering::SeqCst));
                assert!(stream.write_all(b"must not escape").await.is_err());
            }
            let mut stream = fixture(
                v,
                [bytes(&v["context"]), good.clone(), good].concat(),
                Arc::default(),
                Arc::default(),
            );
            let mut actual = Vec::new();
            assert!(stream.read_to_end(&mut actual).await.is_err());
            assert_eq!(
                actual,
                bytes(&v["plaintext"]),
                "only the first authenticated record is delivered"
            );
        }
    }

    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl AsyncRead for DropProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("stopped node must not read IO");
        }
    }
    impl AsyncWrite for DropProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            panic!("stopped node must not write IO");
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("stopped node must not flush IO");
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("stopped node must not shutdown IO");
        }
    }

    #[tokio::test]
    async fn stopped_node_fails_writes_and_releases_owned_io_immediately() {
        let dropped = Arc::new(AtomicBool::new(false));
        let cache = Arc::new(Cache::default());
        let key = Zeroizing::new([0; 96]);
        let mut stream = Records::new(
            Box::new(DropProbe(dropped.clone())),
            key,
            Suite::Aes,
            Aead::new(&[0; 16], &[0; 96], Suite::Aes).unwrap(),
            Aead::new(&[0; 16], &[0; 96], Suite::Aes).unwrap(),
            None,
            None,
            17,
            cache.clone(),
            None,
        );
        cache.close();
        assert_eq!(
            stream.write(b"business").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "Stop error must release the underlying IO before returning"
        );
    }
}
