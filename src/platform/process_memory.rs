use std::{
    ffi::c_void,
    io, mem, ptr,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::Duration,
};

use crate::limits::{
    IOS_TUN_PEAK_OBSERVATION_TARGET_BYTES, IOS_TUN_START_OBSERVATION_TARGET_BYTES,
};

pub(crate) const TELEMETRY_INTERVAL: Duration = Duration::from_secs(30);

const TASK_VM_INFO: libc::task_flavor_t = 22;
const FORTY_MIB: u64 = 40 * 1024 * 1024;
const THRESHOLDS: [MemoryThreshold; 3] = [
    MemoryThreshold {
        bytes: IOS_TUN_START_OBSERVATION_TARGET_BYTES,
        bit: 1 << 0,
        mib: 35,
    },
    MemoryThreshold {
        bytes: FORTY_MIB,
        bit: 1 << 1,
        mib: 40,
    },
    MemoryThreshold {
        bytes: IOS_TUN_PEAK_OBSERVATION_TARGET_BYTES,
        bit: 1 << 2,
        mib: 45,
    },
];

static TELEMETRY_POLICY: MemoryTelemetryPolicy = MemoryTelemetryPolicy::new();

/// Public `TASK_VM_INFO` layout through revision 3. Revision 3 is the first
/// revision that contains `ledger_phys_footprint_peak`; using that fixed,
/// documented prefix avoids depending on newer SDK-only tail fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TaskVmInfoRev3 {
    virtual_size: libc::mach_vm_size_t,
    region_count: libc::integer_t,
    page_size: libc::integer_t,
    resident_size: libc::mach_vm_size_t,
    resident_size_peak: libc::mach_vm_size_t,
    device: libc::mach_vm_size_t,
    device_peak: libc::mach_vm_size_t,
    internal: libc::mach_vm_size_t,
    internal_peak: libc::mach_vm_size_t,
    external: libc::mach_vm_size_t,
    external_peak: libc::mach_vm_size_t,
    reusable: libc::mach_vm_size_t,
    reusable_peak: libc::mach_vm_size_t,
    purgeable_volatile_pmap: libc::mach_vm_size_t,
    purgeable_volatile_resident: libc::mach_vm_size_t,
    purgeable_volatile_virtual: libc::mach_vm_size_t,
    compressed: libc::mach_vm_size_t,
    compressed_peak: libc::mach_vm_size_t,
    compressed_lifetime: libc::mach_vm_size_t,
    phys_footprint: libc::mach_vm_size_t,
    min_address: libc::mach_vm_address_t,
    max_address: libc::mach_vm_address_t,
    ledger_phys_footprint_peak: i64,
    remaining_rev3_ledgers: [i64; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessMemorySnapshot {
    pub current_phys_footprint: u64,
    pub lifetime_peak_phys_footprint: u64,
}

#[derive(Debug, Clone, Copy)]
struct MemoryThreshold {
    bytes: u64,
    bit: u8,
    mib: u8,
}

/// Platform-neutral decision state. The Mach provider is intentionally kept
/// outside this type so host tests can inject arbitrary snapshots and errors.
struct MemoryTelemetryPolicy {
    crossed_thresholds: AtomicU8,
    measurement_failure_warned: AtomicBool,
}

impl MemoryTelemetryPolicy {
    const fn new() -> Self {
        Self {
            crossed_thresholds: AtomicU8::new(0),
            measurement_failure_warned: AtomicBool::new(false),
        }
    }

    fn sample(&self, snapshot: io::Result<ProcessMemorySnapshot>) -> TelemetryObservation {
        match snapshot {
            Ok(snapshot) => {
                let crossed = THRESHOLDS
                    .iter()
                    .filter(|threshold| snapshot.current_phys_footprint >= threshold.bytes)
                    .fold(0_u8, |mask, threshold| mask | threshold.bit);
                let already_crossed = self.crossed_thresholds.fetch_or(crossed, Ordering::Relaxed);
                TelemetryObservation::Snapshot {
                    snapshot,
                    newly_crossed: crossed & !already_crossed,
                }
            }
            Err(error) => TelemetryObservation::MeasurementFailed {
                error,
                first: !self
                    .measurement_failure_warned
                    .swap(true, Ordering::Relaxed),
            },
        }
    }
}

enum TelemetryObservation {
    Snapshot {
        snapshot: ProcessMemorySnapshot,
        newly_crossed: u8,
    },
    MeasurementFailed {
        error: io::Error,
        first: bool,
    },
}

/// Samples process memory for diagnostics only. Neither measurement failure nor
/// any observed footprint can affect the caller's lifecycle result.
pub(crate) fn observe(stage: &'static str) {
    match TELEMETRY_POLICY.sample(snapshot()) {
        TelemetryObservation::Snapshot {
            snapshot,
            newly_crossed,
        } => {
            tracing::info!(
                event = "ios_memory_snapshot",
                stage,
                current_phys_footprint_bytes = snapshot.current_phys_footprint,
                process_lifetime_peak_phys_footprint_bytes = snapshot.lifetime_peak_phys_footprint,
                "iOS TUN memory telemetry"
            );
            for threshold in THRESHOLDS
                .iter()
                .filter(|threshold| newly_crossed & threshold.bit != 0)
            {
                tracing::warn!(
                    event = "ios_memory_observation_target_crossed",
                    stage,
                    current_phys_footprint_bytes = snapshot.current_phys_footprint,
                    process_lifetime_peak_phys_footprint_bytes =
                        snapshot.lifetime_peak_phys_footprint,
                    threshold_bytes = threshold.bytes,
                    threshold_mib = threshold.mib,
                    "iOS TUN current memory crossed an observation threshold"
                );
            }
        }
        TelemetryObservation::MeasurementFailed { error, first } => {
            if first {
                tracing::warn!(
                    event = "ios_memory_measurement_failed",
                    stage,
                    error = %error,
                    "unable to sample iOS TUN memory telemetry"
                );
            }
        }
    }
}

/// Reads current and process-lifetime physical footprint using public
/// `TASK_VM_INFO` fields. Callers must treat failure as telemetry loss only.
#[allow(deprecated)] // libc recommends mach2 for the thin mach_task_self accessor.
pub(crate) fn snapshot() -> io::Result<ProcessMemorySnapshot> {
    let mut info = TaskVmInfoRev3::default();
    let mut count = libc::mach_msg_type_number_t::try_from(
        mem::size_of::<TaskVmInfoRev3>() / mem::size_of::<libc::natural_t>(),
    )
    .expect("TASK_VM_INFO revision 3 count fits the Mach ABI");
    // SAFETY: `info` is the documented, C-compatible TASK_VM_INFO revision 3
    // prefix and `count` describes its exact capacity in natural_t units.
    let result = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            TASK_VM_INFO,
            ptr::from_mut(&mut info).cast::<libc::integer_t>(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return Err(io::Error::other(format!(
            "TASK_VM_INFO failed with Mach error {result}"
        )));
    }
    let peak_field_count = libc::mach_msg_type_number_t::try_from(
        (mem::offset_of!(TaskVmInfoRev3, ledger_phys_footprint_peak) + mem::size_of::<i64>())
            / mem::size_of::<libc::natural_t>(),
    )
    .expect("TASK_VM_INFO peak field count fits the Mach ABI");
    if count < peak_field_count {
        return Err(io::Error::other(format!(
            "TASK_VM_INFO returned {count} words; {peak_field_count} are required for the footprint peak"
        )));
    }
    let peak = u64::try_from(info.ledger_phys_footprint_peak).unwrap_or(0);
    Ok(ProcessMemorySnapshot {
        current_phys_footprint: info.phys_footprint,
        lifetime_peak_phys_footprint: peak,
    })
}

/// Best-effort release of free pages held by Apple's malloc zones after a TUN
/// consumer has stopped. It has no bearing on lifecycle success.
pub(crate) fn relieve_allocator_pressure() {
    unsafe extern "C" {
        fn malloc_zone_pressure_relief(zone: *mut c_void, goal: usize) -> usize;
    }
    // SAFETY: a null zone asks the allocator to inspect all zones; goal zero
    // requests best-effort pressure relief. The API is available on iOS 4.3+.
    let _released = unsafe { malloc_zone_pressure_relief(ptr::null_mut(), 0) };
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    fn snapshot_at(current: u64, lifetime_peak: u64) -> io::Result<ProcessMemorySnapshot> {
        Ok(ProcessMemorySnapshot {
            current_phys_footprint: current,
            lifetime_peak_phys_footprint: lifetime_peak,
        })
    }

    fn sampled(
        policy: &MemoryTelemetryPolicy,
        current: u64,
        lifetime_peak: u64,
    ) -> (ProcessMemorySnapshot, u8) {
        match policy.sample(snapshot_at(current, lifetime_peak)) {
            TelemetryObservation::Snapshot {
                snapshot,
                newly_crossed,
            } => (snapshot, newly_crossed),
            TelemetryObservation::MeasurementFailed { .. } => panic!("unexpected failure"),
        }
    }

    #[test]
    fn thresholds_use_current_and_are_reported_only_once() {
        let policy = MemoryTelemetryPolicy::new();
        let (snapshot, crossed) = sampled(&policy, 35 * 1024 * 1024 - 1, 100 * 1024 * 1024);
        assert_eq!(snapshot.lifetime_peak_phys_footprint, 100 * 1024 * 1024);
        assert_eq!(crossed, 0);
        assert_eq!(
            sampled(&policy, 35 * 1024 * 1024, 100 * 1024 * 1024).1,
            1 << 0
        );
        assert_eq!(
            sampled(&policy, 46 * 1024 * 1024, 100 * 1024 * 1024).1,
            (1 << 1) | (1 << 2)
        );
        assert_eq!(sampled(&policy, 46 * 1024 * 1024, 101 * 1024 * 1024).1, 0);
    }

    #[test]
    fn measurement_failure_is_non_fatal_and_warns_only_once() {
        let policy = MemoryTelemetryPolicy::new();
        for (index, message) in ["injected failure one", "injected failure two"]
            .into_iter()
            .enumerate()
        {
            match policy.sample(Err(io::Error::other(message))) {
                TelemetryObservation::MeasurementFailed { error, first } => {
                    assert_eq!(first, index == 0);
                    assert_eq!(error.to_string(), message);
                }
                TelemetryObservation::Snapshot { .. } => panic!("unexpected snapshot"),
            }
        }
        assert!(matches!(
            policy.sample(snapshot_at(1, 2)),
            TelemetryObservation::Snapshot { .. }
        ));
    }

    #[test]
    fn concurrent_samples_claim_each_threshold_once() {
        let policy = Arc::new(MemoryTelemetryPolicy::new());
        let newly_crossed: u8 = (0..8)
            .map(|_| {
                let policy = policy.clone();
                thread::spawn(move || sampled(&policy, 46 * 1024 * 1024, 50 * 1024 * 1024).1)
            })
            .map(|thread| thread.join().unwrap())
            .fold(0, |mask, crossed| {
                assert_eq!(mask & crossed, 0);
                mask | crossed
            });
        assert_eq!(newly_crossed, (1 << 0) | (1 << 1) | (1 << 2));
    }

    #[test]
    fn apple_process_snapshot_is_nonzero() {
        assert_eq!(mem::size_of::<TaskVmInfoRev3>(), 336);
        assert_eq!(mem::offset_of!(TaskVmInfoRev3, phys_footprint), 144);
        assert_eq!(
            mem::offset_of!(TaskVmInfoRev3, ledger_phys_footprint_peak),
            168
        );
        let snapshot = snapshot().unwrap();
        assert!(snapshot.current_phys_footprint > 0);
        assert!(
            snapshot.lifetime_peak_phys_footprint == 0
                || snapshot.lifetime_peak_phys_footprint >= snapshot.current_phys_footprint
        );
    }
}
