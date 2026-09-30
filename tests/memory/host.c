/* Minimal production-ABI host. No traffic generation, hashing, or JSON parsing.
 * The driver owns lifecycle ordering. F is allowed only after destroyInstance
 * (or an empty calibration); after its acknowledgement there is no allocator,
 * stdio flush, atexit handler or business cleanup, only read(2) and _exit(2). */
#include "observer.h"
#ifndef MEMORY_EMPTY_HOST
#include "vcore.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static char request[65536];

static void output(const char *bytes, size_t size) {
    while (size) {
        ssize_t n = write(STDOUT_FILENO, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) _exit(70);
        bytes += n;
        size -= (size_t)n;
    }
}

static void sample(void) {
    struct memory_sample s;
    char line[512];
    if (memory_self(&s)) _exit(71);
    int n = snprintf(line, sizeof(line),
        "{\"pid\":%d,\"start\":%llu,\"footprint\":%llu,\"peak\":%llu,"
        "\"rss\":%llu,\"user_ns\":%llu,\"system_ns\":%llu}\n",
        getpid(), (unsigned long long)s.start, (unsigned long long)s.footprint,
        (unsigned long long)s.peak, (unsigned long long)s.rss,
        (unsigned long long)s.user_ns, (unsigned long long)s.system_ns);
    if (n <= 0 || (size_t)n >= sizeof(line)) _exit(71);
    output(line, (size_t)n);
}

static int line(void) {
    size_t used = 0;
    while (used + 1 < sizeof(request)) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1) return 0;
        if (c == '\n') { request[used] = 0; return 1; }
        request[used++] = c;
    }
    _exit(72);
}

int main(void) {
    void *held = NULL;
    size_t held_size = 0;
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) return 72;
    signal(SIGPIPE, SIG_IGN);
    sample();
    while (line()) {
        if (!strcmp(request, "S")) sample();
        else if (request[0] == 'D' && request[1] == ' ') {
            char *end;
            long fd = strtol(request + 2, &end, 10);
            if (*end || fd < 0 || fd >= getdtablesize()) _exit(72);
            int flags = fcntl((int)fd, F_GETFL);
            int count = 0;
            for (int current = 0; current < getdtablesize(); ++current)
                if (fcntl(current, F_GETFD) >= 0) ++count;
            char reply[128];
            int size = snprintf(reply, sizeof(reply),
                "{\"original_open\":%s,\"nonblocking\":%s,\"open_fds\":%d}\n",
                flags >= 0 ? "true" : "false",
                flags >= 0 && (flags & O_NONBLOCK) ? "true" : "false", count);
            if (size <= 0 || (size_t)size >= sizeof(reply)) _exit(72);
            output(reply, (size_t)size);
        }
        else if (!strcmp(request, "F")) {
            if (held) _exit(72);
            sample();
            char permit;
            for (;;) {
                ssize_t n = read(STDIN_FILENO, &permit, 1);
                if (n < 0 && errno == EINTR) continue;
                _exit(n == 1 && permit == 'E' ? 0 : 73);
            }
        } else if (!strcmp(request, "X")) raise(SIGKILL);
        else if (!strcmp(request, "R")) {
            if (!held || munmap(held, held_size)) _exit(74);
            held = NULL;
            sample();
        } else if ((request[0] == 'A' || request[0] == 'H') && request[1] == ' ') {
            char *end;
            unsigned long size = strtoul(request + 2, &end, 10);
            if (held || *end || size == 0 || size > 128 * 1024 * 1024) _exit(72);
            volatile unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
            if ((void *)p == MAP_FAILED) _exit(74);
            long page = sysconf(_SC_PAGESIZE);
            if (page <= 0) _exit(74);
            for (size_t i = 0; i < size; i += (size_t)page) p[i] = (unsigned char)i + 1;
            if (request[0] == 'H') { held = (void *)p; held_size = size; }
            else if (munmap((void *)p, size)) _exit(74);
            sample();
        }
#ifndef MEMORY_EMPTY_HOST
        else if (request[0] == 'I' && request[1] == ' ') {
            char *reply = VCoreInvoke(request + 2);
            if (!reply) _exit(75);
            size_t length = strnlen(reply, sizeof(request));
            if (length == sizeof(request)) { VCoreFree(reply); _exit(75); }
            output(reply, length);
            output("\n", 1);
            VCoreFree(reply);
        }
#endif
        else _exit(72);
    }
    return 73; /* Unpermitted parent disappearance is never a valid final exit. */
}
