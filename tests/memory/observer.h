#pragma once
#include <stdint.h>

/* A small, versioned harness ABI. Darwin layouts stay in SDK-compiled C. All
 * memory counters are bytes, CPU counters are nanoseconds, start is Mach ticks. */
struct memory_sample {
    uint64_t start, footprint, peak, rss, user_ns, system_ns;
    uint8_t image_uuid[16];
};
int memory_external(int pid, struct memory_sample *out);
int memory_self(struct memory_sample *out);
