//! External application-to-raw-IP test client, never linked into the measured PID.
//! Unix-stream IPC carries either TCP bytes or length-framed UDP to this client;
//! only complete IPv4/IPv6 + Darwin utun frames cross the inherited socketpair.
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::{Duration as StackDuration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::{UnixDatagram, UnixListener, UnixStream},
    },
    time::{Duration, Instant as Clock},
};

const QUEUE: usize = 256;
const BUFFER: usize = 65536;
const MAX_FLOWS: usize = 256;
const MTU: usize = 1500;

#[derive(Default)]
struct Packets {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}
struct Received(Vec<u8>);
struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        assert!(len <= MTU);
        let mut frame = vec![0; len + 4];
        let result = f(&mut frame[4..]);
        let family: u32 = match frame[4] >> 4 {
            4 => 2,
            6 => 30,
            _ => panic!("invalid IP"),
        };
        frame[..4].copy_from_slice(&family.to_be_bytes());
        self.0.push_back(frame);
        result
    }
}
impl Device for Packets {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Received, Transmit<'_>)> {
        if self.tx.len() == QUEUE {
            return None;
        }
        Some((Received(self.rx.pop_front()?), Transmit(&mut self.tx)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        (self.tx.len() < QUEUE).then_some(Transmit(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Flow {
    control: UnixStream,
    header: Vec<u8>,
    socket: Option<SocketHandle>,
    target: Option<IpEndpoint>,
    udp: bool,
    announced: bool,
    eof: bool,
    read_closed: bool,
    incoming: VecDeque<u8>,
    outgoing: VecDeque<u8>,
    created: Clock,
    local_port: u16,
}
impl Flow {
    fn new(control: UnixStream, local_port: u16) -> io::Result<Self> {
        control.set_nonblocking(true)?;
        Ok(Self {
            control,
            header: Vec::with_capacity(20),
            socket: None,
            target: None,
            udp: false,
            announced: false,
            eof: false,
            read_closed: false,
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            created: Clock::now(),
            local_port,
        })
    }

    fn initialize(
        &mut self,
        interface: &mut Interface,
        sockets: &mut SocketSet<'static>,
    ) -> io::Result<bool> {
        let mut bytes = [0; 20];
        match self.control.read(&mut bytes[..20 - self.header.len()]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => self.header.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        }
        if self.header.first() == Some(&0) {
            return Ok(true);
        }
        if self.header.len() < 20 {
            return Ok(false);
        }
        self.udp = match self.header[0] {
            1 => false,
            2 => true,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let address = match self.header[1] {
            4 => IpAddress::Ipv4(Ipv4Addr::new(
                self.header[4],
                self.header[5],
                self.header[6],
                self.header[7],
            )),
            6 => IpAddress::Ipv6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&self.header[4..20]).unwrap(),
            )),
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let target = IpEndpoint::new(
            address,
            u16::from_be_bytes([self.header[2], self.header[3]]),
        );
        if target.port == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.target = Some(target);
        self.socket = Some(if self.udp {
            let buffer =
                || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 64 * MTU]);
            let mut socket = udp::Socket::new(buffer(), buffer());
            socket.bind(self.local_port).map_err(io::Error::other)?;
            sockets.add(socket)
        } else {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; BUFFER]),
                tcp::SocketBuffer::new(vec![0; BUFFER]),
            );
            socket.set_ack_delay(Some(StackDuration::from_millis(1)));
            socket.set_timeout(Some(StackDuration::from_secs(10)));
            socket
                .connect(interface.context(), target, self.local_port)
                .map_err(io::Error::other)?;
            sockets.add(socket)
        });
        Ok(false)
    }

    fn drive(&mut self, sockets: &mut SocketSet<'static>) -> io::Result<bool> {
        let Some(handle) = self.socket else {
            return Ok(false);
        };
        if !self.announced {
            if !self.udp {
                let socket = sockets.get::<tcp::Socket>(handle);
                if socket.state() == tcp::State::Closed {
                    return Err(io::ErrorKind::ConnectionRefused.into());
                }
                if !socket.may_send() {
                    return Ok(false);
                }
            }
            self.outgoing.push_back(0);
            self.announced = true;
        }
        let mut changed = false;
        // Per-flow and device queues remain bounded under slow readers.
        if !self.eof && self.incoming.len() < BUFFER {
            let mut buffer = [0; 16384];
            let amount = buffer.len().min(BUFFER - self.incoming.len());
            match self.control.read(&mut buffer[..amount]) {
                Ok(0) => {
                    self.eof = true;
                    changed = true;
                }
                Ok(n) => {
                    self.incoming.extend(&buffer[..n]);
                    changed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if self.udp {
            let socket = sockets.get_mut::<udp::Socket>(handle);
            for _ in 0..64 {
                if self.incoming.len() < 2 || !socket.can_send() {
                    break;
                }
                let length = u16::from_be_bytes([self.incoming[0], self.incoming[1]]) as usize;
                if length > 1452 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if self.incoming.len() < length + 2 {
                    break;
                }
                socket
                    .send_slice(
                        &self.incoming.make_contiguous()[2..length + 2],
                        self.target.unwrap(),
                    )
                    .map_err(io::Error::other)?;
                self.incoming.drain(..length + 2);
                changed = true;
            }
            while socket.can_recv() && self.outgoing.len() + MTU + 2 <= BUFFER {
                let (data, meta) = socket.recv().map_err(io::Error::other)?;
                if Some(meta.endpoint) != self.target {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.outgoing.extend((data.len() as u16).to_be_bytes());
                self.outgoing.extend(data);
                changed = true;
            }
        } else {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_send() && !self.incoming.is_empty() {
                let sent = socket
                    .send_slice(self.incoming.make_contiguous())
                    .map_err(io::Error::other)?;
                self.incoming.drain(..sent);
                changed |= sent > 0;
            }
            if self.eof && self.incoming.is_empty() {
                socket.close();
            }
            if socket.can_recv() && self.outgoing.len() < BUFFER {
                let maximum = BUFFER - self.outgoing.len();
                socket
                    .recv(|data| {
                        let n = data.len().min(maximum);
                        self.outgoing.extend(&data[..n]);
                        changed |= n > 0;
                        (n, ())
                    })
                    .map_err(io::Error::other)?;
            }
            if !socket.may_recv() && self.outgoing.is_empty() && !self.read_closed {
                self.control.shutdown(Shutdown::Write)?;
                self.read_closed = true;
            }
        }
        if !self.outgoing.is_empty() {
            match self.control.write(self.outgoing.make_contiguous()) {
                Ok(n) => {
                    self.outgoing.drain(..n);
                    changed |= n > 0;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(changed)
    }
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 3 {
        return Err(io::Error::other(
            "usage: tun-driver inherited-fd unix-control-path",
        ));
    }
    let descriptor: i32 = arguments[1].parse().map_err(io::Error::other)?;
    if descriptor < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // The parent passes a dedicated owned duplicate, never the core's endpoint.
    let raw = unsafe { UnixDatagram::from_raw_fd(descriptor) };
    raw.set_nonblocking(true)?;
    let listener = UnixListener::bind(&arguments[2])?;
    listener.set_nonblocking(true)?;
    let mut packets = Packets::default();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 20260930;
    let started = Clock::now();
    let timestamp = || Instant::from_micros(started.elapsed().as_micros() as i64);
    let mut interface = Interface::new(config, &mut packets, timestamp());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 24))
            .unwrap();
        addresses
            .push(IpCidr::new("fd00:5643:6f72:6500::2".parse().unwrap(), 64))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(192, 0, 2, 1))
        .unwrap();
    interface
        .routes_mut()
        .add_default_ipv6_route("fd00:5643:6f72:6500::1".parse().unwrap())
        .unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: Vec<Flow> = Vec::new();
    let mut port = 10000_u16;
    let (mut sent, mut received, mut opened, mut errors, mut peak) =
        (0_u64, 0_u64, 0_u64, 0_u64, 0_usize);
    loop {
        let mut changed = false;
        while flows.len() < MAX_FLOWS {
            match listener.accept() {
                Ok((stream, _)) => {
                    while flows.iter().any(|flow| flow.local_port == port) {
                        port = if port == 65000 { 10000 } else { port + 1 };
                    }
                    flows.push(Flow::new(stream, port)?);
                    port = if port == 65000 { 10000 } else { port + 1 };
                    opened += 1;
                    peak = peak.max(flows.len());
                    changed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        while packets.rx.len() < QUEUE {
            let mut frame = [0_u8; MTU + 5];
            match raw.recv(&mut frame) {
                Ok(n) => {
                    if !(24..=MTU + 4).contains(&n)
                        || !matches!(
                            (
                                frame[..4].try_into().map(u32::from_be_bytes).unwrap(),
                                frame[4] >> 4
                            ),
                            (2, 4) | (30, 6)
                        )
                    {
                        return Err(io::Error::other("invalid utun frame"));
                    }
                    packets.rx.push_back(frame[4..n].to_vec());
                    received += 1;
                    changed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        interface.poll(timestamp(), &mut packets, &mut sockets);
        let mut index = 0;
        while index < flows.len() {
            let flow = &mut flows[index];
            let mut remove = false;
            if flow.socket.is_none() {
                match flow.initialize(&mut interface, &mut sockets) {
                    Ok(true) => {
                        println!(
                            "{{\"complete\":true,\"ip_packets_sent\":{sent},\"ip_packets_received\":{received},\"opened\":{opened},\"peak_flows\":{peak},\"flow_errors\":{errors},\"active_at_shutdown\":{}}}",
                            flows.len() - 1
                        );
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(_) => {
                        errors += 1;
                        remove = true;
                    }
                }
            }
            if !remove {
                match flow.drive(&mut sockets) {
                    Ok(progress) => changed |= progress,
                    Err(_) => {
                        errors += 1;
                        remove = true;
                    }
                }
                if !flow.announced && flow.created.elapsed() > Duration::from_secs(5) {
                    remove = true;
                    errors += 1;
                }
                if let Some(handle) = flow.socket {
                    remove |= if flow.udp {
                        flow.eof
                    } else {
                        let socket = sockets.get::<tcp::Socket>(handle);
                        matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
                            && flow.outgoing.is_empty()
                    };
                }
            }
            if remove {
                let removed = flows.swap_remove(index);
                if let Some(handle) = removed.socket {
                    sockets.remove(handle);
                }
            } else {
                index += 1;
            }
        }
        interface.poll(timestamp(), &mut packets, &mut sockets);
        while let Some(frame) = packets.tx.front() {
            match raw.send(frame) {
                Ok(n) if n == frame.len() => {
                    packets.tx.pop_front();
                    sent += 1;
                    changed = true;
                }
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        if !changed {
            let mut fds = Vec::with_capacity(flows.len() + 2);
            fds.push(libc::pollfd {
                fd: raw.as_raw_fd(),
                events: libc::POLLIN
                    | if packets.tx.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            });
            fds.push(libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            for flow in &flows {
                let events = if !flow.eof && flow.incoming.len() < BUFFER {
                    libc::POLLIN
                } else {
                    0
                } | if flow.outgoing.is_empty() {
                    0
                } else {
                    libc::POLLOUT
                };
                fds.push(libc::pollfd {
                    fd: flow.control.as_raw_fd(),
                    events,
                    revents: 0,
                });
            }
            // Valid borrowed fds and initialized writable storage; no ownership transfer.
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 1) };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("external TUN client: {error}");
        std::process::exit(1);
    }
}
