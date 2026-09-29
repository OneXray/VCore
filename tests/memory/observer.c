#include "observer.h"
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <stddef.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int memory_external(int pid, struct memory_sample *out) {
    struct rusage_info_v4 info = {0};
    mach_timebase_info_data_t timebase;
    if (pid <= 0 || proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&info))
        return -1;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) return -1;
    if (!info.ri_proc_start_abstime || !info.ri_lifetime_max_phys_footprint) {
        errno = ENODATA;
        return -1;
    }
    *out = (struct memory_sample){
        .start = info.ri_proc_start_abstime,
        .footprint = info.ri_phys_footprint,
        .peak = info.ri_lifetime_max_phys_footprint,
        .rss = info.ri_resident_size,
        .user_ns = (uint64_t)((__uint128_t)info.ri_user_time * timebase.numer / timebase.denom),
        .system_ns = (uint64_t)((__uint128_t)info.ri_system_time * timebase.numer / timebase.denom),
    };
    memcpy(out->image_uuid, info.ri_uuid, sizeof(out->image_uuid));
    return 0;
}

int memory_self(struct memory_sample *out) {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (memory_external(getpid(), out)) return -1;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count)
            != KERN_SUCCESS ||
        count < (offsetof(task_vm_info_data_t, ledger_phys_footprint_peak) +
                 sizeof(info.ledger_phys_footprint_peak)) / sizeof(natural_t) ||
        info.ledger_phys_footprint_peak <= 0) return -1;
    out->footprint = info.phys_footprint;
    out->peak = (uint64_t)info.ledger_phys_footprint_peak;
    out->rss = info.resident_size;
    return 0;
}
