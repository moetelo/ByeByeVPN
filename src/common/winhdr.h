// SPDX-License-Identifier: GPL-3.0-or-later
// shared platform header. on Windows this fixes the winsock/win32 include
// order; on POSIX it provides a thin compatibility shim so the sources that
// were written against the Winsock/conio surface compile unchanged.
// include this before any other project header in cpp files that touch
// sockets / adapters / icmp / the keyboard.
#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <conio.h>

#else // ---- POSIX ---------------------------------------------------------

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <strings.h>

// --- Winsock type/name surface mapped onto BSD sockets ---------------------
using SOCKET = int;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
using DWORD = std::uint32_t;   // safety net for stray Windows-typed locals

inline int closesocket(int s) { return ::close(s); }
#define ioctlsocket ioctl
#define WSAGetLastError() (errno)
#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK EWOULDBLOCK
#endif
#ifndef WSAEINPROGRESS
#define WSAEINPROGRESS EINPROGRESS   // POSIX non-blocking connect() in-progress
#endif
#ifndef WSAECONNREFUSED
#define WSAECONNREFUSED ECONNREFUSED
#endif
#ifndef WSAECONNRESET
#define WSAECONNRESET ECONNRESET
#endif
#ifndef WSAETIMEDOUT
#define WSAETIMEDOUT ETIMEDOUT
#endif
#define InetNtopA     inet_ntop
#define gai_strerrorA gai_strerror
#define _stricmp      strcasecmp
#define _strnicmp     strncasecmp

inline void Sleep(unsigned long ms) { ::usleep(ms * 1000UL); }

// --- conio "press a key" surface (only tcp_scan.cpp's skip-phase uses it) ---
// lazily drops the tty into cbreak mode and restores it at exit. a no-op when
// stdin is not a terminal (piped / headless), so the skip feature simply stays
// inert rather than corrupting the terminal.
inline termios& bbv_saved_termios() { static termios t{}; return t; }
inline bool&     bbv_raw_active()    { static bool b = false; return b; }
inline void bbv_restore_termios() {
    if (bbv_raw_active()) {
        tcsetattr(STDIN_FILENO, TCSANOW, &bbv_saved_termios());
        bbv_raw_active() = false;
    }
}
inline void bbv_enable_cbreak() {
    if (bbv_raw_active() || !isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &bbv_saved_termios()) != 0) return;
    termios raw = bbv_saved_termios();
    raw.c_lflag &= ~(unsigned)(ICANON | ECHO);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    bbv_raw_active() = true;
    std::atexit(bbv_restore_termios);
}
inline int _kbhit() {
    if (!isatty(STDIN_FILENO)) return 0;
    bbv_enable_cbreak();
    fd_set fs; FD_ZERO(&fs); FD_SET(STDIN_FILENO, &fs);
    timeval tv{0, 0};
    return select(STDIN_FILENO + 1, &fs, nullptr, nullptr, &tv) > 0;
}
inline int _getch() {
    unsigned char c = 0;
    return ::read(STDIN_FILENO, &c, 1) == 1 ? (int)c : -1;
}

#endif // _WIN32

// portable recv timeout. Winsock's SO_RCVTIMEO takes a DWORD of milliseconds,
// POSIX takes a struct timeval — passing the DWORD form on Linux silently sets
// no timeout (wrong optlen), so every caller must go through this.
inline void sock_set_recv_timeout(SOCKET s, int ms) {
#ifdef _WIN32
    DWORD to = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
#else
    timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
}
