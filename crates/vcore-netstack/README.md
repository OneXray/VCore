# vcore-netstack

`vcore-netstack` is VCore's bounded userspace raw-IP netstack. It accepts
IPv4/IPv6 packets from a TUN device, exposes intercepted TCP streams and UDP
datagrams to async Rust code, and returns generated raw-IP packets.

The default local buffers are intentionally small for an iOS TUN runtime;
VCore does not assume the host process role:

- 32 KiB total buffering per TCP direction, configurable;
- bounded raw-packet, TCP-accept and UDP-datagram queues;
- TCP flow state reclaimed by protocol completion or idle timeout;
- no unbounded channel;
- cancellation plus a stop completion barrier.

See `NOTICE` for the upstream implementation studied while implementing this
crate and the material differences from it.

## Main API

```rust,ignore
let stack = vcore_netstack::NetStack::start(config)?;
let vcore_netstack::NetStackParts {
    packet_sink,
    packet_stream,
    tcp_listener,
    udp_socket,
    control,
    stats,
} = stack.into_parts();

packet_sink.send(raw_ip_packet).await?;
let tcp = tcp_listener.accept().await;
let udp = udp_socket.recv().await;
control.stop().await;
```

`NetStackControl::stop()` returns only after the driver has released all
smoltcp sockets and woken pending TCP operations.
