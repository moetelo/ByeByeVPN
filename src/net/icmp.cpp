// SPDX-License-Identifier: GPL-3.0-or-later
#include "icmp.h"
#include "../common/winhdr.h"
#include "../common/tspu.h"

#include <vector>

using std::vector;
using std::string;

#ifdef _WIN32

TraceResult trace_hops(const std::string& target_ip, int max_hops) {
    TraceResult r;
    // resolve once — only IPv4 (ICMP4).
    struct in_addr dst{}; dst.s_addr = 0;
    struct addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    if (getaddrinfo(target_ip.c_str(), nullptr, &hints, &ai) != 0 || !ai) return r;
    for (auto* p = ai; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            dst = ((sockaddr_in*)p->ai_addr)->sin_addr;
            break;
        }
    }
    freeaddrinfo(ai);
    if (dst.s_addr == 0) return r;

    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return r;

    // standard windows ping payload (32 bytes), identical to what ping.exe sends
    const char payload[] = "abcdefghijklmnopqrstuvwabcdefghi";
    const DWORD rcvsz = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8 + 128;
    vector<unsigned char> rcv(rcvsz);

    int prev_rtt = 0;
    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        IP_OPTION_INFORMATION opt{};
        opt.Ttl = (unsigned char)ttl;
        opt.Tos = 0;
        opt.Flags = 0;
        opt.OptionsSize = 0;
        opt.OptionsData = nullptr;
        DWORD n = IcmpSendEcho2(h, nullptr, nullptr, nullptr, dst.s_addr,
                                (LPVOID)payload, sizeof(payload),
                                &opt, rcv.data(), (DWORD)rcv.size(), 1500);
        TraceHop hop; hop.ttl = ttl;
        if (n > 0) {
            auto* rep = (ICMP_ECHO_REPLY*)rcv.data();
            struct in_addr a{}; a.s_addr = rep->Address;
            char buf[INET_ADDRSTRLEN] = {0};
            InetNtopA(AF_INET, &a, buf, sizeof(buf));
            hop.addr = buf;
            hop.rtt_ms = (int)rep->RoundTripTime;
            if (prev_rtt > 0) {
                int delta = hop.rtt_ms - prev_rtt;
                if (delta > r.max_rtt_jump_ms) r.max_rtt_jump_ms = delta;
            }
            if (hop.rtt_ms > 150) ++r.long_hops;
            prev_rtt = hop.rtt_ms;
            r.hops.push_back(hop);
            if (rep->Status == IP_SUCCESS && rep->Address == dst.s_addr) {
                r.reached_target = true;
                break;
            }
        } else {
            hop.rtt_ms = -1;
            r.hops.push_back(hop);
        }
    }
    IcmpCloseHandle(h);
    r.hop_count = 0;
    for (auto& hop: r.hops) if (hop.rtt_ms >= 0) ++r.hop_count;
    for (auto& hop: r.hops) {
        if (hop.rtt_ms >= 0 && looks_like_tspu_hop(hop.addr)) ++r.tspu_hops;
    }
    r.ok = (r.hop_count > 0);
    return r;
}

#else // ---- POSIX: unprivileged ICMP-echo traceroute ----------------------

#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <chrono>
#include <cstring>

namespace {

using clk = std::chrono::steady_clock;
int ms_since(clk::time_point t0) {
    return (int)std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t0).count();
}

uint16_t icmp_checksum(const void* data, int len) {
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    for (; len > 1; len -= 2) sum += *p++;
    if (len == 1) sum += *(const uint8_t*)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

// open an ICMP socket: unprivileged datagram first (needs only a permissive
// net.ipv4.ping_group_range), raw as a CAP_NET_RAW/root fallback.
// non-blocking is essential: select() can report the socket readable when only
// the IP_RECVERR error queue has data, and a blocking recvfrom() on the (empty)
// main queue would then stall forever.
SOCKET open_icmp_socket() {
    SOCKET s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
    if (s != INVALID_SOCKET) return s;
    return socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
}

// drain one ICMP error off the queue (a router's TIME_EXCEEDED / a filter's
// DEST_UNREACH). returns the offender IP, or "" if nothing usable.
string read_icmp_error(SOCKET s) {
    char cbuf[512], dbuf[256];
    sockaddr_in from{};
    iovec iov{dbuf, sizeof(dbuf)};
    msghdr msg{};
    msg.msg_name = &from;      msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;        msg.msg_iovlen = 1;
    msg.msg_control = cbuf;    msg.msg_controllen = sizeof(cbuf);
    if (recvmsg(s, &msg, MSG_ERRQUEUE) < 0) return "";
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVERR) continue;
        auto* ee = (sock_extended_err*)CMSG_DATA(c);
        if (ee->ee_origin != SO_EE_ORIGIN_ICMP) continue;
        sockaddr* off = SO_EE_OFFENDER(ee);
        if (off->sa_family != AF_INET) continue;
        char buf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &((sockaddr_in*)off)->sin_addr, buf, sizeof(buf));
        return buf;
    }
    return "";
}

} // namespace

TraceResult trace_hops(const std::string& target_ip, int max_hops) {
    TraceResult r;

    // resolve once — IPv4 only (ICMP4).
    sockaddr_in dst{}; dst.sin_family = AF_INET;
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(target_ip.c_str(), nullptr, &hints, &ai) != 0 || !ai) return r;
    bool have = false;
    for (auto* p = ai; p; p = p->ai_next)
        if (p->ai_family == AF_INET) { dst.sin_addr = ((sockaddr_in*)p->ai_addr)->sin_addr; have = true; break; }
    freeaddrinfo(ai);
    if (!have) return r;

    SOCKET s = open_icmp_socket();
    if (s == INVALID_SOCKET) return r;               // no ICMP perms at all
    int on = 1;
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));

    // 32-byte payload, same bytes ping/ping.exe use.
    const char payload[] = "abcdefghijklmnopqrstuvwabcdefghi";
    const int  plen = (int)sizeof(payload) - 1;
    const uint16_t id = (uint16_t)(getpid() & 0xffff);

    unsigned char pkt[8 + sizeof(payload)];
    memcpy(pkt + 8, payload, plen);

    int prev_rtt = 0;
    const int per_hop_ms = 1500;
    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        auto* h = (icmphdr*)pkt;
        h->type = ICMP_ECHO; h->code = 0; h->checksum = 0;
        h->un.echo.id = htons(id); h->un.echo.sequence = htons((uint16_t)ttl);
        h->checksum = icmp_checksum(pkt, 8 + plen);

        auto t0 = clk::now();
        sendto(s, pkt, 8 + plen, 0, (sockaddr*)&dst, sizeof(dst));

        TraceHop hop; hop.ttl = ttl; hop.rtt_ms = -1;
        bool reached_here = false;
        for (;;) {
            int remain = per_hop_ms - ms_since(t0);
            if (remain <= 0) break;
            fd_set rd, er; FD_ZERO(&rd); FD_ZERO(&er);
            FD_SET(s, &rd); FD_SET(s, &er);
            timeval tv{remain / 1000, (remain % 1000) * 1000};
            if (select((int)s + 1, &rd, nullptr, &er, &tv) <= 0) break;

            // errqueue readiness can surface in either fd set depending on the
            // kernel, so always try draining an ICMP error (an intermediate-hop
            // TIME_EXCEEDED) before looking for a normal echo reply.
            string off = read_icmp_error(s);
            if (!off.empty()) { hop.addr = off; hop.rtt_ms = ms_since(t0); break; }

            sockaddr_in src{}; socklen_t sl = sizeof(src);
            char rbuf[256];
            int n = recvfrom(s, rbuf, sizeof(rbuf), 0, (sockaddr*)&src, &sl);
            if (n > 0) {
                char buf[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf));
                hop.addr = buf; hop.rtt_ms = ms_since(t0);
                if (src.sin_addr.s_addr == dst.sin_addr.s_addr) reached_here = true;
                break;
            }
        }

        if (hop.rtt_ms >= 0) {
            if (prev_rtt > 0) {
                int delta = hop.rtt_ms - prev_rtt;
                if (delta > r.max_rtt_jump_ms) r.max_rtt_jump_ms = delta;
            }
            if (hop.rtt_ms > 150) ++r.long_hops;
            prev_rtt = hop.rtt_ms;
        }
        r.hops.push_back(hop);
        if (reached_here) { r.reached_target = true; break; }
    }
    closesocket(s);

    for (auto& hop : r.hops) if (hop.rtt_ms >= 0) ++r.hop_count;
    for (auto& hop : r.hops)
        if (hop.rtt_ms >= 0 && looks_like_tspu_hop(hop.addr)) ++r.tspu_hops;
    r.ok = (r.hop_count > 0);
    return r;
}

#endif // _WIN32