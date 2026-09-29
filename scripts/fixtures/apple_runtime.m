/* Production-library consumer, not a Network Extension or memory benchmark.
 * All echo services live in the harness-owned container. This process owns only
 * the DUT inbound and a Unix datagram pair used as a synthetic utun descriptor. */
#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include "vcore.h"

extern int vcore_abi_smoke(int, char **);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL apple runtime line %d (errno %d)\n", __LINE__, errno); \
    exit(1); \
} } while (0)

static NSDictionary *invoke(NSString *method, NSString *instance, NSDictionary *payload,
                            BOOL success) {
    NSMutableDictionary *request = [@{@"apiVersion": @5, @"method": method,
                                     @"payload": payload} mutableCopy];
    if (instance) request[@"instanceId"] = instance;
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
    char *raw = VCoreInvoke(json.UTF8String);
    CHECK(raw != NULL);
    NSData *bytes = [NSData dataWithBytes:raw length:strlen(raw)];
    VCoreFree(raw);
    NSDictionary *response = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
    CHECK([response isKindOfClass:[NSDictionary class]]);
    if ([response[@"success"] boolValue] != success)
        fprintf(stderr, "Invoke %s expected success=%d\n", method.UTF8String, success);
    CHECK([response[@"success"] boolValue] == success);
    return success ? response[@"data"] : @{};
}

static int new_socket(int family, int kind) {
    int fd = socket(family, kind, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static struct sockaddr_in endpoint(const char *ip, uint16_t port) {
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
                                  .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, ip, &address.sin_addr) == 1);
    return address;
}

static int connect_to(const char *ip, uint16_t port) {
    int fd = new_socket(AF_INET, SOCK_STREAM);
    struct sockaddr_in address = endpoint(ip, port);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    CHECK(result == 0 || errno == EINPROGRESS);
    struct pollfd wait = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&wait, 1, 5000) == 1);
    int error = -1;
    socklen_t size = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0);
    CHECK(fcntl(fd, F_SETFL, 0) == 0);
    return fd;
}

static void exact(int fd, void *bytes, size_t length, BOOL write) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t size = write ? send(fd, (char *)bytes + offset, length - offset, 0)
                             : recv(fd, (char *)bytes + offset, length - offset, 0);
        CHECK(size > 0);
        offset += (size_t)size;
    }
}

static uint16_t origin(int *control, const char *ip, uint8_t mode) {
    *control = connect_to(ip, 24000);
    exact(*control, &mode, 1, YES);
    uint16_t port;
    exact(*control, &port, sizeof(port), NO);
    return ntohs(port);
}

static uint16_t vacant_port(void) {
    int fd = new_socket(AF_INET, SOCK_STREAM);
    struct sockaddr_in address = endpoint("127.0.0.1", 0);
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr *)&address, &size) == 0);
    close(fd);
    return ntohs(address.sin_port);
}

static void check_port_released(uint16_t port) {
    for (int kind = 0; kind < 2; kind++) {
        int fd = new_socket(AF_INET, kind ? SOCK_DGRAM : SOCK_STREAM);
        int one = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        struct sockaddr_in address = endpoint("127.0.0.1", port);
        CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
        close(fd);
    }
}

static void address_bytes(uint8_t *bytes, const char *ip, uint16_t port) {
    bytes[0] = 1;
    CHECK(inet_pton(AF_INET, ip, bytes + 1) == 1);
    bytes[5] = (uint8_t)(port >> 8);
    bytes[6] = (uint8_t)port;
}

static int socks(uint16_t port, uint8_t command, const char *ip, uint16_t remote,
                 struct sockaddr_in *relay) {
    int fd = connect_to("127.0.0.1", port);
    uint8_t hello[] = {5, 1, 0}, response[10];
    exact(fd, hello, sizeof(hello), YES);
    exact(fd, response, 2, NO);
    CHECK(response[0] == 5 && response[1] == 0);
    uint8_t request[10] = {5, command, 0};
    address_bytes(request + 3, ip, remote);
    exact(fd, request, sizeof(request), YES);
    exact(fd, response, sizeof(response), NO);
    CHECK(response[0] == 5 && response[1] == 0 && response[2] == 0 && response[3] == 1);
    if (relay) {
        *relay = endpoint("127.0.0.1", (uint16_t)((response[8] << 8) | response[9]));
        CHECK(memcmp(response + 4, &relay->sin_addr, 4) == 0);
    }
    return fd;
}

static const uint8_t payload[] = "vcore-apple-platform-data";

static void socks_traffic(uint16_t port, const char *ip) {
    int observer;
    uint16_t remote = origin(&observer, ip, 13);
    int tcp = socks(port, 1, ip, remote, NULL);
    uint8_t marker;
    exact(observer, &marker, 1, NO);
    CHECK(marker == 'A');
    exact(tcp, (void *)payload, sizeof(payload), YES);
    uint8_t reply[sizeof(payload)];
    exact(tcp, reply, sizeof(reply), NO);
    CHECK(memcmp(payload, reply, sizeof(reply)) == 0);
    close(tcp);
    exact(observer, &marker, 1, NO);
    CHECK(marker == 'D');
    close(observer);

    remote = origin(&observer, ip, 4);
    struct sockaddr_in relay;
    int control = socks(port, 3, "0.0.0.0", 0, &relay);
    int udp = new_socket(AF_INET, SOCK_DGRAM);
    uint8_t request[10 + sizeof(payload)] = {0};
    address_bytes(request + 3, ip, remote);
    memcpy(request + 10, payload, sizeof(payload));
    CHECK(sendto(udp, request, sizeof(request), 0, (struct sockaddr *)&relay, sizeof(relay)) == sizeof(request));
    uint8_t datagram[sizeof(request) + 1];
    CHECK(recv(udp, datagram, sizeof(datagram), 0) == sizeof(request));
    CHECK(memcmp(datagram, request, sizeof(request)) == 0);
    uint8_t observed[4 + sizeof(payload)];
    exact(observer, observed, sizeof(observed), NO);
    CHECK(((observed[0] << 8) | observed[1]) == sizeof(payload));
    CHECK(memcmp(observed + 4, payload, sizeof(payload)) == 0);
    close(udp); close(control); close(observer);
}

static uint16_t checksum(const uint8_t *bytes, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2)
        sum += ((uint16_t)bytes[i] << 8) | (i + 1 < length ? bytes[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

static void put16(uint8_t *buffer, uint16_t value) {
    buffer[0] = (uint8_t)(value >> 8); buffer[1] = (uint8_t)value;
}

static void put32(uint8_t *buffer, uint32_t value) {
    value = htonl(value); memcpy(buffer, &value, 4);
}

static uint32_t get32(const uint8_t *buffer) {
    uint32_t value; memcpy(&value, buffer, 4); return ntohl(value);
}

static void packet(int fd, const char *ip, uint16_t port, uint8_t protocol,
                   uint32_t seq, uint32_t ack, uint8_t flags, BOOL data) {
    uint8_t bytes[1504] = {0}, pseudo[1500] = {0};
    uint8_t *header = bytes + 4, *segment = header + 20;
    size_t size = (protocol == 6 ? 20 : 8) + (data ? sizeof(payload) : 0);
    put32(bytes, AF_INET);
    header[0] = 0x45; put16(header + 2, (uint16_t)(20 + size));
    header[6] = 0x40; header[8] = 64; header[9] = protocol;
    CHECK(inet_pton(AF_INET, "192.0.2.10", header + 12) == 1);
    CHECK(inet_pton(AF_INET, ip, header + 16) == 1);
    put16(header + 10, checksum(header, 20));
    put16(segment, 12000); put16(segment + 2, port);
    if (protocol == 6) {
        put32(segment + 4, seq); put32(segment + 8, ack);
        segment[12] = 0x50; segment[13] = flags; put16(segment + 14, UINT16_MAX);
    } else put16(segment + 4, (uint16_t)size);
    if (data) memcpy(segment + (protocol == 6 ? 20 : 8), payload, sizeof(payload));
    memcpy(pseudo, header + 12, 8); pseudo[9] = protocol; put16(pseudo + 10, (uint16_t)size);
    memcpy(pseudo + 12, segment, size);
    uint16_t sum = checksum(pseudo, size + 12);
    put16(segment + (protocol == 6 ? 16 : 6), sum == 0 ? UINT16_MAX : sum);
    CHECK(send(fd, bytes, size + 24, 0) == (ssize_t)(size + 24));
}

static size_t receive_packet(int fd, uint8_t *packet, uint8_t protocol,
                             const char *ip, uint16_t port) {
    uint8_t bytes[1504], expected[4], pseudo[1500] = {0};
    CHECK(inet_pton(AF_INET, ip, expected) == 1);
    ssize_t size = recv(fd, bytes, sizeof(bytes), 0);
    CHECK(size >= 32 && get32(bytes) == AF_INET);
    size -= 4; memcpy(packet, bytes + 4, (size_t)size);
    CHECK(packet[0] == 0x45 && checksum(packet, 20) == 0 && packet[9] == protocol);
    CHECK(((packet[2] << 8) | packet[3]) == size);
    CHECK(memcmp(packet + 12, expected, 4) == 0 && get32(packet + 16) == 0xc000020a);
    CHECK(((packet[20] << 8) | packet[21]) == port);
    CHECK(((packet[22] << 8) | packet[23]) == 12000);
    memcpy(pseudo, packet + 12, 8); pseudo[9] = protocol;
    put16(pseudo + 10, (uint16_t)(size - 20)); memcpy(pseudo + 12, packet + 20, (size_t)size - 20);
    CHECK(checksum(pseudo, (size_t)size - 8) == 0);
    return (size_t)size;
}

static void tun_traffic(int fd, const char *ip) {
    int observer;
    uint8_t reply[1500];
    uint16_t port = origin(&observer, ip, 4);
    packet(fd, ip, port, 17, 0, 0, 0, YES);
    CHECK(receive_packet(fd, reply, 17, ip, port) == 28 + sizeof(payload));
    CHECK(memcmp(reply + 28, payload, sizeof(payload)) == 0);
    close(observer);

    port = origin(&observer, ip, 13);
    packet(fd, ip, port, 6, 1, 0, 2, NO);
    CHECK(receive_packet(fd, reply, 6, ip, port) >= 40);
    CHECK((reply[33] & 0x12) == 0x12 && get32(reply + 28) == 2);
    uint32_t server_seq = get32(reply + 24) + 1;
    packet(fd, ip, port, 6, 2, server_seq, 0x18, YES);
    uint8_t marker;
    exact(observer, &marker, 1, NO); CHECK(marker == 'A');
    size_t received = 0;
    for (unsigned packets = 0; received < sizeof(payload) && packets < 16; packets++) {
        size_t size = receive_packet(fd, reply, 6, ip, port);
        size_t offset = 20 + (size_t)(reply[32] >> 4) * 4;
        CHECK(offset >= 40 && offset <= size);
        size_t length = size - offset;
        CHECK(received + length <= sizeof(payload));
        if (length) {
            CHECK(get32(reply + 24) == server_seq + received);
            CHECK(memcmp(reply + offset, payload + received, length) == 0);
            received += length;
        }
    }
    CHECK(received == sizeof(payload));
    packet(fd, ip, port, 6, 2 + sizeof(payload), server_seq + sizeof(payload), 0x14, NO);
    close(observer);
}

static NSString *prepare(BOOL tun, uint16_t port) {
    NSString *instance = invoke(@"createInstance", nil, @{}, YES)[@"instanceId"];
    // JSON avoids YAML flow-list comma splitting of the single MATCH rule.
    // Schema requires a node even for a DIRECT route. This unused literal is
    // never dialled and introduces no server or host DNS dependency.
    NSDictionary *configuration = @{@"socks-port": @(port), @"tun": @{@"enable": @(tun)},
        @"proxies": @[@{@"name": @"unused", @"type": @"socks5", @"server": @"127.0.0.1", @"port": @9}],
        @"proxy-groups": @[@{@"name": @"route", @"type": @"select", @"proxies": @[@"DIRECT"]}],
        @"rules": @[@"MATCH,route"]};
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:configuration options:0 error:NULL];
    NSString *config = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
    invoke(@"prepare", instance, @{@"configYaml": config}, YES);
    return instance;
}

static void memory_sample(void) {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    CHECK(task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS);
    CHECK(count >= TASK_VM_INFO_REV3_COUNT && info.phys_footprint > 0);
    CHECK(info.ledger_phys_footprint_peak == 0 || (uint64_t)info.ledger_phys_footprint_peak >= info.phys_footprint);
    printf("Apple simulator memory sample: current=%llu lifetime_peak=%lld (not device acceptance)\n",
           (unsigned long long)info.phys_footprint, (long long)info.ledger_phys_footprint_peak);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        CHECK(argc == 3);
        signal(SIGPIPE, SIG_IGN);
        CHECK(vcore_abi_smoke(0, NULL) == 0);
        invoke(@"initialize", nil, @{@"dataDir": @(argv[1])}, YES);
        for (int error = 0; error < 4; error++) {
            int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
            if (error != 3) CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
            int flags = fcntl(pair[0], F_GETFL);
            NSString *instance = prepare(YES, 0);
            NSMutableDictionary *arguments = [@{@"tunFd": @(error == 2 ? -1 : pair[0]),
                                                @"tunFraming": error == 0 ? @"rawIp" : @"utun"} mutableCopy];
            if (error == 1) [arguments removeObjectForKey:@"tunFraming"];
            invoke(@"start", instance, arguments, NO);
            invoke(@"destroyInstance", instance, @{}, YES);
            CHECK(fcntl(pair[0], F_GETFL) == flags);
            close(pair[0]); close(pair[1]);
        }
        for (int round = 0; round < 3; round++) {
            for (int tun = 0; tun < 2; tun++) {
                uint16_t port = vacant_port();
                int pair[2] = {-1, -1};
                NSMutableDictionary *arguments = [NSMutableDictionary dictionary];
                if (tun) {
                    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
                    CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
                    struct timeval timeout = {.tv_sec = 5};
                    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
                    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
                    arguments[@"tunFd"] = @(pair[0]); arguments[@"tunFraming"] = @"utun";
                }
                NSString *instance = prepare(tun, port);
                invoke(@"start", instance, arguments, YES);
                CHECK([invoke(@"getState", instance, @{}, YES)[@"state"] isEqual:@"running"]);
                socks_traffic(port, argv[2]);
                if (tun) tun_traffic(pair[1], argv[2]);
                // Exercise the actual 30-second mobile TUN telemetry task once,
                // not only the immediate prepare/start/stop observation hooks.
                if (tun && round == 0) sleep(31);
                memory_sample();
                if (round != 2) {
                    invoke(@"stop", instance, @{}, YES);
                    invoke(@"stop", instance, @{}, YES);
                    CHECK([invoke(@"getState", instance, @{}, YES)[@"state"] isEqual:@"stopped"]);
                }
                invoke(@"destroyInstance", instance, @{}, YES);
                invoke(@"getState", instance, @{}, NO);
                if (tun) {
                    CHECK(fcntl(pair[0], F_GETFL) & O_NONBLOCK);
                    close(pair[0]); close(pair[1]);
                }
                check_port_released(port);
            }
        }
        puts("PASS Apple runtime: 3 local/TUN lifecycle pairs, SOCKS5 TCP/UDP, synthetic utun TCP/UDP, fd ownership, invalid inputs, memory API");
    }
    return 0;
}
