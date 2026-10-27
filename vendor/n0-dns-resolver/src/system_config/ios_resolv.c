/* iOS configuration reader. Public SDK libresolv calls; no DNS query is sent. */
#include <arpa/inet.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int append(char *out, size_t cap, size_t *used, const char *format, ...) {
    if (*used >= cap) return -1;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(out + *used, cap - *used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= cap - *used) return -1;
    *used += (size_t)n;
    return 0;
}

int n0_read_ios_dns(char *out, size_t cap) {
    if (!out || !cap) return -1;
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) return -1;
    union res_sockaddr_union servers[MAXNS];
    memset(servers, 0, sizeof(servers));
    int count = res_getservers(&state, servers, MAXNS);
    size_t used = 0;
    int result = -1;
    if (count <= 0 || count > MAXNS) goto done;
    for (int i = 0; i < count; ++i) {
        char address[INET6_ADDRSTRLEN];
        unsigned port;
        if (servers[i].sin.sin_family == AF_INET) {
            if (!inet_ntop(AF_INET, &servers[i].sin.sin_addr, address, sizeof(address))) goto done;
            port = ntohs(servers[i].sin.sin_port);
            if (append(out, cap, &used, "server %s:%u\n", address, port ? port : 53) != 0) goto done;
        } else if (servers[i].sin6.sin6_family == AF_INET6) {
            if (!inet_ntop(AF_INET6, &servers[i].sin6.sin6_addr, address, sizeof(address))) goto done;
            port = ntohs(servers[i].sin6.sin6_port);
            if (servers[i].sin6.sin6_scope_id) {
                if (append(out, cap, &used, "server [%s%%%u]:%u\n", address,
                           servers[i].sin6.sin6_scope_id, port ? port : 53) != 0) goto done;
            } else if (append(out, cap, &used, "server [%s]:%u\n", address, port ? port : 53) != 0) goto done;
        } else goto done;
    }
    for (int i = 0; i <= MAXDNSRCH && state.dnsrch[i]; ++i) {
        if (strnlen(state.dnsrch[i], 254) > 253) goto done;
        if (append(out, cap, &used, "search %s\n", state.dnsrch[i]) != 0) goto done;
    }
    if (append(out, cap, &used, "ndots %u\n", state.ndots) != 0) goto done;
    result = (int)used;
done:
    res_ndestroy(&state);
    return result;
}
