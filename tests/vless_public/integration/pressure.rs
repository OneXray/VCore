use super::*;

const TCP_GROUPS: [&str; 4] = ["socks5", "ss-v3", "tuic", "httpupgrade"];
const UDP_GROUPS: [&str; 4] = ["ss-uot", "ss-uot-v3", "tuic", "httpupgrade"];

struct Flows {
    tcp: Vec<(TcpStream, Origin)>,
    udp: Vec<Association>,
    setup_us: Vec<u64>,
    profiles: Value,
}

impl Flows {
    fn open(f: &Value, port: u16, controller: u16, generation: usize) -> Self {
        let mut flows = Self {
            tcp: Vec::with_capacity(20),
            udp: Vec::with_capacity(20),
            setup_us: Vec::with_capacity(40),
            profiles: json!({"tcp":[],"udp":[]}),
        };
        for (tcp_group, udp_group) in TCP_GROUPS.into_iter().zip(UDP_GROUPS) {
            for index in 0..5 {
                let profile = |group| {
                    let options = f["profile_groups"][group].as_array().unwrap();
                    options[(generation + index) % options.len()]
                        .as_str()
                        .unwrap()
                };
                let tcp_profile = profile(tcp_group);
                runtime::select(controller, tcp_profile);
                let start = Instant::now();
                flows.tcp.push(runtime::live(port, f));
                flows.setup_us.push(start.elapsed().as_micros() as u64);
                flows.profiles["tcp"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(tcp_profile));
                let udp_profile = profile(udp_group);
                runtime::select(controller, udp_profile);
                let start = Instant::now();
                let mut udp = Association::new(f, port, false, false);
                udp.exchange(&payload(generation, flows.udp.len(), 0, true));
                flows.udp.push(udp);
                flows.setup_us.push(start.elapsed().as_micros() as u64);
                flows.profiles["udp"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(udp_profile));
            }
        }
        assert_eq!((flows.tcp.len(), flows.udp.len()), (20, 20));
        flows
    }

    fn exchange(&mut self, generation: usize, wave: usize) {
        for (index, ((tcp, _), udp)) in self.tcp.iter_mut().zip(&mut self.udp).enumerate() {
            runtime::exchange(tcp, &payload(generation, index, wave, false));
            udp.exchange(&payload(generation, index, wave, true));
        }
    }

    fn assert_tcp_closed(&mut self) {
        for (tcp, _) in &mut self.tcp {
            runtime::assert_closed(tcp);
        }
    }
}

fn payload(generation: usize, index: usize, wave: usize, udp: bool) -> Vec<u8> {
    let mut bytes = vec![u8::from(udp); 257];
    for (slot, value) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip([generation, index, wave])
    {
        slot.copy_from_slice(&(value as u64).to_be_bytes());
    }
    bytes
}

fn close_peer(f: &Value) {
    let mut client = socket(f["peer_controller"].as_str().unwrap().parse().unwrap());
    client.write_all(b"DELETE /connections HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer synthetic-integration-control\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204"));
}

fn start(f: &Value, probe: &ResourceProbe) -> (Core, u16, u16) {
    let port = free_port();
    let controller = free_port();
    let mut members = Vec::new();
    for group in TCP_GROUPS.into_iter().chain(UDP_GROUPS) {
        for profile in f["profile_groups"][group].as_array().unwrap() {
            let name = profile.as_str().unwrap();
            if !members.contains(&name) {
                members.push(name);
            }
        }
    }
    let nodes: Vec<_> = members
        .iter()
        .map(|protocol| {
            let mut node = f["nodes"][protocol].clone();
            node["name"] = json!(protocol);
            node
        })
        .collect();
    let yaml = json!({"socks-port":port,"external-controller":format!("127.0.0.1:{controller}"),"secret":"fixture-only","proxies":nodes,"proxy-groups":[{"name":"inner","type":"select","proxies":members}],"rules":["MATCH,inner"]});
    (probe.scope_sync(|| Core::start(&yaml)), port, controller)
}

fn sample(probe: &ResourceProbe) -> Value {
    json!({"heap_in_use":heap_in_use(),"rss_kib":rss_kib(),"fd":lifecycle::fd_count(),"resources":probe.snapshot(),"queues":probe.queues()})
}

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

fn heap_in_use() -> usize {
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
    // SAFETY: macOS SDK C layout; NULL requests aggregate allocator statistics.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut statistics) };
    statistics.size_in_use
}

fn stop_quiet(
    core: Core,
    probe: &ResourceProbe,
    port: u16,
    controller: u16,
    baseline: usize,
) -> Value {
    let start = Instant::now();
    core.stop();
    let stop_ms = start.elapsed().as_millis();
    let resources = probe.snapshot();
    assert!(stop_ms < 5000 && resources.is_idle());
    let after_fd = lifecycle::fd_count();
    assert!(
        after_fd <= baseline,
        "FD baseline {baseline}, after Stop {after_fd}"
    );
    let after_stop = sample(probe);
    let rebound = (
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap(),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap(),
        TcpListener::bind((Ipv4Addr::LOCALHOST, controller)).unwrap(),
    );
    let quiet = Instant::now();
    while quiet.elapsed() < Duration::from_secs(5) {
        assert_eq!(probe.snapshot(), resources);
        assert!(lifecycle::fd_count() <= baseline + 3);
        thread::sleep(Duration::from_millis(25));
    }
    drop(rebound);
    json!({"stop_ms":stop_ms,"after_stop":after_stop,"quiet_seconds":quiet.elapsed().as_secs_f64(),"quiet":sample(probe),"ports_rebound":true})
}

#[test]
#[ignore = "owned INTEGRATION container fixture required"]
fn rebuild() {
    run_rebuild(100);
}

#[test]
#[ignore = "owned INTEGRATION container fixture required; development subset only"]
fn rebuild_tracer() {
    run_rebuild(3);
}

fn idle_baseline() -> (usize, usize) {
    let cold = lifecycle::fd_count();
    // Tokio's process-global Unix signal pair survives individual runtimes.
    // Initialize ONLY an empty IO driver before freezing the baseline; never
    // warm away leaked protocol resources or grant post-Stop cleanup grace.
    drop(
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap(),
    );
    let idle = lifecycle::fd_count();
    assert!(idle >= cold && idle - cold <= 2);
    (cold, idle)
}

fn run_rebuild(count: usize) {
    let f = fixture();
    initialize(&f);
    let probe = ResourceProbe::default();
    let (cold_fd, baseline) = idle_baseline();
    let mut case = RecordedCase::new("INTEGRATION-REBUILD", "forty_flows_same_session");
    case.checkpoint("baseline", probe.snapshot());
    let (core, port, controller) = start(&f, &probe);
    let mut cycles = Vec::new();
    for generation in 0..count {
        let mut flows = Flows::open(&f, port, controller, generation);
        flows.exchange(generation, 1);
        let active = sample(&probe);
        close_peer(&f);
        flows.assert_tcp_closed();
        let setup = flows.setup_us.clone();
        let profiles = flows.profiles.clone();
        drop(flows);
        cycles.push(json!({"generation":generation,"tcp":20,"udp":20,"per_group_tcp":5,"per_group_udp":5,"flow_profiles":profiles,"active":active,"setup_us":setup,"fault":"owned-peer-connections-closed","new_clients":true,"after_clients":sample(&probe)}));
        println!("INTEGRATION rebuild: {}/{count}", generation + 1);
    }
    let stopped = stop_quiet(core, &probe, port, controller, baseline);
    case.resources(probe.snapshot());
    observe(
        json!({"count":count,"same_running_session":true,"tcp_groups":TCP_GROUPS,"udp_groups":UDP_GROUPS,"cold_fd":cold_fd,"baseline_fd":baseline,"cycles":cycles,"stopped":stopped}),
    );
}

fn median(values: impl Iterator<Item = u64>) -> u64 {
    let mut values: Vec<_> = values.collect();
    values.sort_unstable();
    assert!(!values.is_empty());
    (values[(values.len() - 1) / 2] + values[values.len() / 2]) / 2
}

fn append_sample(value: &Value) {
    let path = std::env::var("VCORE_INTEGRATION_OBSERVATIONS").unwrap() + ".jsonl";
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    writeln!(file, "{value}").unwrap();
}

#[test]
#[ignore = "owned INTEGRATION container fixture required; at least 1800 seconds"]
fn soak() {
    run_soak(1800);
}

#[test]
#[ignore = "owned INTEGRATION container fixture required; development subset only"]
fn soak_tracer() {
    run_soak(65);
}

fn run_soak(seconds: u64) {
    let f = fixture();
    initialize(&f);
    let (cold_fd, baseline) = idle_baseline();
    let probe = ResourceProbe::default();
    let mut case = RecordedCase::new("INTEGRATION-SOAK", "mixed_forty_flows");
    case.checkpoint("baseline", probe.snapshot());
    let (core, port, controller) = start(&f, &probe);
    let mut flows = Flows::open(&f, port, controller, 0);
    let first_setup = flows.setup_us.clone();
    let first_profiles = flows.profiles.clone();
    let first_median = median(first_setup.iter().copied());
    let start = Instant::now();
    let mut waves = 0;
    let mut switches = Vec::new();
    let mut faults = Vec::new();
    let mut samples = Vec::new();
    let mut next_switch = 1;
    let mut next_fault = 60;
    let mut next_sample = if seconds >= 1800 { 300 } else { 0 };
    while start.elapsed() < Duration::from_secs(seconds) {
        flows.exchange(faults.len(), waves);
        waves += 1;
        while start.elapsed().as_secs() >= next_switch {
            let options = f["profile_groups"][TCP_GROUPS[switches.len() % 4]]
                .as_array()
                .unwrap();
            runtime::select(
                controller,
                options[(switches.len() / 4) % options.len()]
                    .as_str()
                    .unwrap(),
            );
            switches.push(start.elapsed().as_secs_f64());
            next_switch += 1;
        }
        if start.elapsed().as_secs() >= next_fault {
            let fault = start.elapsed().as_secs_f64();
            close_peer(&f);
            flows.assert_tcp_closed();
            drop(flows);
            flows = Flows::open(&f, port, controller, faults.len() + 1);
            faults.push(json!({"start":fault,"end":start.elapsed().as_secs_f64(),"old_tcp_closed":20,"new_tcp":20,"new_udp":20,"replay":false}));
            next_fault += 60;
        }
        if start.elapsed().as_secs() >= next_sample {
            let mut point = sample(&probe);
            point["seconds"] = json!(start.elapsed().as_secs_f64());
            point["waves"] = json!(waves);
            point["faults"] = json!(faults.len());
            append_sample(&point);
            samples.push(point);
            next_sample += 60;
            println!(
                "INTEGRATION soak: {:.1}/{seconds}s, waves={waves}, faults={}",
                start.elapsed().as_secs_f64(),
                faults.len()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let elapsed = start.elapsed().as_secs_f64();
    let last_setup = flows.setup_us.clone();
    let last_profiles = flows.profiles.clone();
    let last_median = median(last_setup.iter().copied());
    assert!(last_median <= first_median * 2);
    let active_end = sample(&probe);
    drop(flows);
    let stopped = stop_quiet(core, &probe, port, controller, baseline);
    case.resources(probe.snapshot());
    let mut report = json!({"seconds":elapsed,"requested_seconds":seconds,"tcp_groups":TCP_GROUPS,"udp_groups":UDP_GROUPS,"tcp":20,"udp":20,"per_group_tcp":5,"per_group_udp":5,"first_profiles":first_profiles,"last_profiles":last_profiles,"waves":waves,"normal_verified_bytes":waves*20*2*2*257,"normal_corruption":0,"normal_misdirection":0,"normal_unexpected_loss":0,"switches":switches,"faults":faults,"cold_fd":cold_fd,"baseline_fd":baseline,"samples":samples,"first_setup_us":first_setup,"last_setup_us":last_setup,"first_setup_median_us":first_median,"last_setup_median_us":last_median,"active_end":active_end,"stopped":stopped});
    if seconds >= 1800 {
        assert!(samples.len() >= 25 && faults.len() >= 29 && switches.len() >= 1799);
        let early = &samples[..10];
        let late = &samples[samples.len() - 10..];
        let first_heap = median(early.iter().map(|p| p["heap_in_use"].as_u64().unwrap()));
        let last_heap = median(late.iter().map(|p| p["heap_in_use"].as_u64().unwrap()));
        let allowed = (1024 * 1024).max(first_heap / 20);
        report["heap"] =
            json!({"early_median":first_heap,"late_median":last_heap,"allowed_growth":allowed});
        // Persist the complete curve even if its final acceptance fails.
        observe(report.clone());
        assert!(
            last_heap <= first_heap + allowed,
            "heap growth exceeds INTEGRATION bound"
        );
        for kind in 0..8 {
            let maximum = |points: &[Value]| {
                points
                    .iter()
                    .map(|p| p["resources"]["counts"][kind]["current"].as_u64().unwrap())
                    .max()
                    .unwrap()
            };
            assert!(
                maximum(late) <= maximum(early),
                "growing live resource kind {kind}"
            );
        }
        assert!(
            late.iter().map(|p| p["fd"].as_u64().unwrap()).max()
                <= early.iter().map(|p| p["fd"].as_u64().unwrap()).max()
        );
        assert!(
            samples
                .iter()
                .all(|p| p["queues"].as_array().unwrap().iter().all(|q| {
                    if q["kind"] == "hysteria2_udp" {
                        q["peak"] == 0 && q["capacity"] == 0
                    } else {
                        q["peak"].as_u64().unwrap() > 0
                            && q["peak"].as_u64() <= q["capacity"].as_u64()
                    }
                }))
        );
    }
    observe(report);
}
