/* Передает проверяемые данные через настоящий сокет выбранного приложения. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK 65536
#define MAX_BYTES (256u * 1024u * 1024u)

static unsigned char buffer[BLOCK];

static int transfer(SOCKET socket, void *bytes, int length, int sending)
{
    unsigned char *cursor = bytes;
    while (length) {
        int count = sending ? send(socket, (const char *)cursor, length, 0)
                            : recv(socket, (char *)cursor, length, 0);
        if (count <= 0) return 0;
        cursor += count;
        length -= count;
    }
    return 1;
}

static void pace(uint64_t rate, uint64_t offset, LARGE_INTEGER frequency, LARGE_INTEGER start)
{
    if (!rate) return;
    double target = (double)offset * frequency.QuadPart / rate;
    for (;;) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double remaining = target - (now.QuadPart - start.QuadPart);
        if (remaining <= 0) return;
        double milliseconds = remaining * 1000.0 / frequency.QuadPart;
        Sleep(milliseconds >= 1000.0 ? 1000 : (DWORD)milliseconds + 1);
    }
}

static int bulk(SOCKET socket, int upload, uint64_t total, char observed[65],
                uint64_t rate, LARGE_INTEGER frequency)
{
    unsigned char header[17] = { upload ? 'U' : rate ? 'P' : 'D' };
    for (unsigned index = 0; index < 8; index++)
        header[8 - index] = (unsigned char)(total >> (index * 8));
    if (!upload && rate)
        for (unsigned index = 0; index < 8; index++)
            header[16 - index] = (unsigned char)(rate >> (index * 8));
    if (!transfer(socket, header, !upload && rate ? 17 : 9, 1)) return 0;
    if (!upload && !transfer(socket, observed, 64, 0)) return 0;
    LARGE_INTEGER started;
    QueryPerformanceCounter(&started);
    for (uint64_t offset = 0; offset < total;) {
        int count = (int)((total - offset) > BLOCK ? BLOCK : total - offset);
        if (upload)
            for (int index = 0; index < count; index++)
                buffer[index] = (unsigned char)((offset + index) % 251);
        if (!transfer(socket, buffer, count, upload)) return 0;
        if (!upload)
            for (int index = 0; index < count; index++)
                if (buffer[index] != (unsigned char)((offset + index) % 251)) return 0;
        offset += count;
        if (upload) pace(rate, offset, frequency, started);
    }
    return !upload || transfer(socket, observed, 64, 0);
}

static uint64_t time_ticks(FILETIME value)
{
    return ((uint64_t)value.dwHighDateTime << 32) | value.dwLowDateTime;
}

static uint64_t active_cpu(void)
{
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) return UINT64_MAX;
    return time_ticks(kernel) + time_ticks(user) - time_ticks(idle);
}

static int compare(const void *left, const void *right)
{
    double a = *(const double *)left, b = *(const double *)right;
    return a > b ? 1 : a < b ? -1 : 0;
}

static int latency(SOCKET socket, LARGE_INTEGER frequency, double *p95, char observed[65])
{
    double samples[100];
    for (unsigned index = 0; index < 100; index++) {
        LARGE_INTEGER start, end;
        unsigned char query[4] = { 'A', 'R', (unsigned char)index, 0 };
        char response[128];
        QueryPerformanceCounter(&start);
        if (send(socket, (const char *)query, sizeof(query), 0) != sizeof(query)) return 0;
        int size = recv(socket, response, sizeof(response), 0);
        QueryPerformanceCounter(&end);
        if (size != 64 + sizeof(query) || memcmp(response + 64, query, sizeof(query))) return 0;
        memcpy(observed, response, 64);
        samples[index] = 1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart;
        Sleep(5);
    }
    qsort(samples, 100, sizeof(samples[0]), compare);
    *p95 = samples[94];
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 5 || (argc - 5) % 2) return 2;
    const char *output = NULL;
    uint64_t rate = 0;
    for (int index = 5; index < argc; index += 2) {
        if (!strcmp(argv[index], "--output") && !output) output = argv[index + 1];
        else if (!strcmp(argv[index], "--rate") && !rate) {
            char *end = NULL;
            rate = strtoull(argv[index + 1], &end, 10);
            if (!rate || rate > 125000000 || !end || *end) return 2;
        } else return 2;
    }
    int upload = !strcmp(argv[1], "upload"), timing = !strcmp(argv[1], "latency");
    if (!upload && !timing && strcmp(argv[1], "download")) return 2;
    char *end = NULL;
    unsigned long port = strtoul(argv[3], &end, 10);
    if (!port || port > 65535 || !end || *end) return 2;
    uint64_t total = strtoull(argv[4], &end, 10);
    if (!total || total > MAX_BYTES || !end || *end) return 2;
    if (rate && (timing || total > rate * 120)) return 2;
    if (output && !freopen(output, "wb", stdout)) return 3;
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 3;
    SOCKET socket = WSASocketW(AF_INET, timing ? SOCK_DGRAM : SOCK_STREAM,
                              timing ? IPPROTO_UDP : IPPROTO_TCP, NULL, 0, 0);
    if (socket == INVALID_SOCKET) { WSACleanup(); return 3; }
    DWORD timeout = 15000;
    struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons((u_short)port) };
    int ready = InetPtonA(AF_INET, argv[2], &peer.sin_addr) == 1 &&
        !setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) &&
        !setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) &&
        !connect(socket, (const struct sockaddr *)&peer, sizeof(peer));
    LARGE_INTEGER frequency, start, finish;
    QueryPerformanceFrequency(&frequency);
    uint64_t cpu_before = active_cpu();
    QueryPerformanceCounter(&start);
    char observed[65] = { 0 };
    double p95 = 0;
    int success = ready && (timing ? latency(socket, frequency, &p95, observed)
                                   : bulk(socket, upload, total, observed, rate, frequency));
    QueryPerformanceCounter(&finish);
    uint64_t cpu_after = active_cpu();
    int error = success ? 0 : WSAGetLastError();
    closesocket(socket);
    WSACleanup();
    if (cpu_before == UINT64_MAX || cpu_after == UINT64_MAX) return 3;
    /* В ответе разрешены только адрес и служебный префикс, без JSON-инъекции. */
    for (unsigned index = 0; index < 64 && observed[index]; index++)
        if (!strchr("observed=0123456789abcdefABCDEF:.", observed[index])) return 3;
    double seconds = (double)(finish.QuadPart - start.QuadPart) / frequency.QuadPart;
    printf("{\"ok\":%s,\"bytes\":%llu,\"seconds\":%.9f,\"mbps\":%.6f,"
           "\"guest_active_cpu_seconds\":%.7f,\"p95_ms\":%.6f,\"reply\":\"%s\",\"error\":%d,"
           "\"configured_bytes_per_second\":%llu}\n",
           success ? "true" : "false", (unsigned long long)(timing ? 0 : total), seconds,
           timing || seconds <= 0 ? 0 : 8.0 * total / seconds / 1000000.0,
           (cpu_after - cpu_before) / 10000000.0, p95, observed, error, (unsigned long long)rate);
    return success ? 0 : 1;
}
