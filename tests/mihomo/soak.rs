//! Explicit wall-clock soak, separate from fast deterministic regression tests.
use super::*;
use groups::{TcpFlow, UdpFlow};

fn rss_kib() -> u64 {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[cfg(target_os = "macos")]
fn heap_in_use() -> usize {
    // macOS SDK malloc/malloc.h: NULL sums every malloc zone. This reads
    // allocator counters only; it does not walk or log payload allocations.
    #[repr(C)]
    #[derive(Default)]
    struct Statistics {
        blocks_in_use: std::ffi::c_uint,
        size_in_use: usize,
        max_size_in_use: usize,
        size_allocated: usize,
    }
    unsafe extern "C" {
        fn malloc_zone_statistics(zone: *mut std::ffi::c_void, statistics: *mut Statistics);
    }
    let mut statistics = Statistics::default();
    // SAFETY: the SDK's C layout matches Statistics, the output is writable,
    // and a null zone explicitly requests aggregate process statistics.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut statistics) };
    statistics.size_in_use
}

fn open_flows(proxy: SocketAddr, controller: SocketAddr) -> (Vec<TcpFlow>, Vec<UdpFlow>, Duration) {
    let started = Instant::now();
    let mut tcp = Vec::with_capacity(16);
    let mut udp = Vec::with_capacity(16);
    for index in 0..16 {
        groups::select(controller, &format!("edge-{}", index % 4));
        tcp.push(TcpFlow::open(proxy));
        let mut flow = UdpFlow::open(proxy);
        flow.exchange(index as u8);
        udp.push(flow);
    }
    (tcp, udp, started.elapsed())
}

#[cfg(target_os = "macos")]
pub(super) fn recovery_probe(controller_port: u16, socks_port: u16, fixtures: &Value) {
    combinations::close_peer_connections(fixtures);
    let baseline_fd = ss_lifecycle::open_fd_count();
    let baseline_heap = heap_in_use();
    let baseline_rss = rss_kib();
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, controller_port));
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let nodes: Vec<Value> = fixtures["last"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let mut node = node.clone();
            node["name"] = json!(format!("edge-{index}"));
            node
        })
        .collect();
    let config = json!({"socks-port":socks_port,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":nodes,"proxy-groups":[{"name":"inner","type":"select","proxies":["edge-0","edge-1","edge-2","edge-3"]}],"rules":["MATCH,inner"]});
    let core = Core::start(&config.to_string());
    println!(
        "RECOVERY baseline: heap_in_use={baseline_heap}, rss_kib={baseline_rss}, fd={baseline_fd:?}"
    );
    let started = Instant::now();
    for round in 0..100 {
        println!("RUN recovery round {round}");
        let (mut tcp, mut udp, _) = open_flows(proxy, controller);
        for (index, (tcp, udp)) in tcp.iter_mut().zip(&mut udp).enumerate() {
            tcp.exchange(index as u8);
            udp.exchange(index as u8);
        }
        if round % 10 == 0 || round == 99 {
            println!(
                "RECOVERY active: round={round}, heap_in_use={}, rss_kib={}, fd={:?}",
                heap_in_use(),
                rss_kib(),
                ss_lifecycle::open_fd_count()
            );
        }
        combinations::close_peer_connections(fixtures);
        for flow in &mut tcp {
            flow.assert_closed();
        }
        drop((tcp, udp));
        combinations::close_peer_connections(fixtures);
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "recovery fixture exceeded 120-second watchdog"
        );
    }
    core.stop();
    ss_lifecycle::assert_fd_returned(baseline_fd);
    drop(TcpListener::bind(proxy).unwrap());
    drop(UdpSocket::bind(proxy).unwrap());
    drop(TcpListener::bind(controller).unwrap());
    println!(
        "RECOVERY result: cycles=100, elapsed_ms={}, heap_in_use={}, rss_kib={}, fd={:?}; inspect resource trend",
        started.elapsed().as_millis(),
        heap_in_use(),
        rss_kib(),
        ss_lifecycle::open_fd_count()
    );
}

pub(super) fn probe(controller_port: u16, socks_port: u16, fixtures: &Value, seconds: u64) {
    assert!((1..=7200).contains(&seconds));
    combinations::close_peer_connections(fixtures);
    let baseline_fd = ss_lifecycle::open_fd_count();
    let baseline_rss = rss_kib();
    let controller = SocketAddr::from((Ipv4Addr::LOCALHOST, controller_port));
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let nodes: Vec<Value> = fixtures["last"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let mut node = node.clone();
            node["name"] = json!(format!("edge-{index}"));
            node
        })
        .collect();
    let config = json!({"socks-port":socks_port,"external-controller":controller.to_string(),"secret":"fixture-controller-only","proxies":nodes,"proxy-groups":[{"name":"inner","type":"select","proxies":["edge-0","edge-1","edge-2","edge-3"]}],"rules":["MATCH,inner"]});
    let core = Core::start(&config.to_string());
    let (mut tcp, mut udp, latency) = open_flows(proxy, controller);
    let warm_rss = rss_kib();
    let warm_fd = ss_lifecycle::open_fd_count();
    let mut peak_rss = warm_rss;
    let mut peak_fd = warm_fd;
    println!(
        "SOAK baseline: idle_rss_kib={baseline_rss}, idle_fd={baseline_fd:?}, active_rss_kib={warm_rss}, active_fd={warm_fd:?}, open_32_flows_ms={}",
        latency.as_millis()
    );
    let started = Instant::now();
    let mut last_switch = Instant::now();
    let mut last_sample = Instant::now();
    let mut last_disconnect = Instant::now();
    let mut waves: u64 = 0;
    let mut switches: u64 = 0;
    let mut disconnects: u64 = 0;
    let mut max_wave = Duration::ZERO;
    let mut last_latency = latency;
    while started.elapsed() < Duration::from_secs(seconds) {
        let wave = Instant::now();
        for (index, (tcp, udp)) in tcp.iter_mut().zip(&mut udp).enumerate() {
            let marker = (waves as u8).wrapping_add(index as u8);
            tcp.exchange(marker);
            udp.exchange(marker.wrapping_add(32));
        }
        max_wave = max_wave.max(wave.elapsed());
        waves += 1;
        if last_switch.elapsed() >= Duration::from_secs(1) {
            groups::select(controller, &format!("edge-{}", switches % 4));
            switches += 1;
            last_switch = Instant::now();
        }
        if last_disconnect.elapsed() >= Duration::from_secs(60) {
            // Close this harness's peers' accepted connections, not listeners.
            // Existing TCP must terminate; recovery uses explicitly new clients.
            combinations::close_peer_connections(fixtures);
            for flow in &mut tcp {
                flow.assert_closed();
            }
            drop(tcp);
            drop(udp);
            combinations::close_peer_connections(fixtures);
            (tcp, udp, last_latency) = open_flows(proxy, controller);
            disconnects += 1;
            last_disconnect = Instant::now();
        }
        if last_sample.elapsed() >= Duration::from_secs(30) {
            let rss = rss_kib();
            let fd = ss_lifecycle::open_fd_count();
            peak_rss = peak_rss.max(rss);
            peak_fd = peak_fd.max(fd);
            println!(
                "SOAK sample: elapsed_s={}, waves={waves}, rss_kib={rss}, fd={fd:?}, switches={switches}, disconnects={disconnects}, max_wave_ms={}",
                started.elapsed().as_secs(),
                max_wave.as_millis()
            );
            last_sample = Instant::now();
        }
        thread::sleep(Duration::from_millis(50));
    }
    let active_end_rss = rss_kib();
    let active_end_fd = ss_lifecycle::open_fd_count();
    core.stop();
    for flow in &mut tcp {
        flow.assert_closed();
    }
    drop((tcp, udp));
    combinations::close_peer_connections(fixtures);
    ss_lifecycle::assert_fd_returned(baseline_fd);
    drop(TcpListener::bind(proxy).unwrap());
    drop(UdpSocket::bind(proxy).unwrap());
    drop(TcpListener::bind(controller).unwrap());
    let bytes = waves * 16 * 2 * 2 * 257;
    println!(
        "SOAK result: elapsed_s={}, waves={waves}, verified_payload_bytes={bytes}, payload_bytes_per_s={}, switches={switches}, disconnects={disconnects}, peak_rss_kib={peak_rss}, active_end_rss_kib={active_end_rss}, after_stop_rss_kib={}, peak_fd={peak_fd:?}, active_end_fd={active_end_fd:?}, after_stop_fd={:?}, last_open_32_ms={}",
        started.elapsed().as_secs(),
        bytes / started.elapsed().as_secs().max(1),
        rss_kib(),
        ss_lifecycle::open_fd_count(),
        last_latency.as_millis()
    );
    if seconds < 1800 {
        println!("PASS short soak fixture only; 30-minute acceptance NOT RUN");
    } else {
        assert!(disconnects > 0 && switches > 0);
        println!(
            "PASS I07 wall-clock mixed soak; inspect resource samples before phase acceptance"
        );
    }
}
