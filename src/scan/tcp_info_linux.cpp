// SPDX-License-Identifier: GPL-3.0-or-later
//
// Isolated translation unit for reading a connected socket's TCP_INFO on Linux.
//
// glibc's <netinet/tcp.h> ships a stale copy of struct tcp_info — it omits
// tcpi_snd_wnd on most glibc versions (2.35 / ubuntu 22.04, 2.39 / ubuntu
// 24.04, ...). The rest of the tree pulls <netinet/tcp.h> in transitively (via
// winhdr.h), so it can't see that field. The kernel's <linux/tcp.h> layout is
// authoritative and always current, but the two headers redefine each other
// and cannot coexist in one TU — hence this file includes <linux/tcp.h> alone.
#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>

#ifndef TCP_INFO
#define TCP_INFO 11
#endif

// negotiated send MSS + the peer's advertised send window, straight from the
// kernel's struct tcp_info. returns false on getsockopt failure. called from
// snapshot_tcp_info() in tcpfp.cpp.
bool bbv_tcp_snapshot(int fd, unsigned* mss, unsigned* snd_wnd) {
    struct tcp_info ti{};
    socklen_t len = sizeof(ti);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0) return false;
    *mss     = ti.tcpi_snd_mss;
    *snd_wnd = ti.tcpi_snd_wnd;
    return true;
}
#endif // __linux__
