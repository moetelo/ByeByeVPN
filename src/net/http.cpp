// SPDX-License-Identifier: GPL-3.0-or-later
#include "http.h"
#include "../common/winhdr.h"
#include "../common/util.h"

#include <chrono>
#include <string>
#include <vector>

using std::string;
using std::vector;

#ifdef _WIN32

HttpResp http_get(const string& url, int timeout_ms, const string& accept) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    URL_COMPONENTS u{}; u.dwStructSize = sizeof(u);
    wchar_t host[256] = {0}, path[1024] = {0};
    u.lpszHostName = host; u.dwHostNameLength = 255;
    u.lpszUrlPath = path;  u.dwUrlPathLength  = 1023;
    std::wstring wurl = s2ws(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &u)) { r.err = "bad url"; return r; }

    // bare GET, no UA. JSON endpoints don't need anything else.
    HINTERNET hS = WinHttpOpen(L"", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = "open"; return r; }
    WinHttpSetTimeouts(hS, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    // force empty UA, winhttp sneaks a default one in otherwise
    WinHttpSetOption(hS, WINHTTP_OPTION_USER_AGENT, (LPVOID)L"", 0);
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    WinHttpSetOption(hS, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));

    HINTERNET hC = WinHttpConnect(hS, host, u.nPort, 0);
    if (!hC) { r.err = "connect"; WinHttpCloseHandle(hS); return r; }
    DWORD flags = (u.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) { r.err = "req"; WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return r; }
    // optional Accept header (content-negotiating endpoints only; empty for the
    // bare-GET callers). -1L length tells WinHTTP to measure the string itself.
    LPCWSTR hdr_ptr = WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hdr_len = 0;
    std::wstring hdrs;
    if (!accept.empty()) {
        hdrs = s2ws("Accept: " + accept + "\r\n");
        hdr_ptr = hdrs.c_str();
        hdr_len = (DWORD)-1L;
    }
    if (!WinHttpSendRequest(hR, hdr_ptr, hdr_len,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hR, nullptr)) {
        r.err = "io " + std::to_string(GetLastError());
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return r;
    }
    DWORD st = 0, sz = sizeof(st);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &st, &sz, nullptr);
    r.status = (int)st;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;
        vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(hR, buf.data(), avail, &got) || got == 0) break;
        r.body.append(buf.data(), got);
        if (r.body.size() > 512 * 1024) break;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

#else // ---- POSIX: bare GET over the existing TCP layer + OpenSSL ----------

#include "tcp.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <cstdlib>

namespace {

struct ParsedUrl { bool https; string host; int port; string path; bool ok; };

ParsedUrl parse_url(const string& url) {
    ParsedUrl p{false, "", 80, "/", false};
    string u = url;
    size_t sp = u.find("://");
    string scheme;
    if (sp != string::npos) { scheme = u.substr(0, sp); u = u.substr(sp + 3); }
    if      (scheme == "https") { p.https = true;  p.port = 443; }
    else if (scheme == "http")  { p.https = false; p.port = 80;  }
    else return p;                                   // only http/https

    size_t slash = u.find('/');
    string hostport = (slash == string::npos) ? u : u.substr(0, slash);
    p.path = (slash == string::npos) ? "/" : u.substr(slash);
    if (p.path.empty()) p.path = "/";

    // hostname[:port] — our callers never use IPv6 literals, so a plain rfind
    // is safe. skip the port split if a ']' is present (defensive).
    size_t colon = hostport.rfind(':');
    if (colon != string::npos && hostport.find(']') == string::npos) {
        p.host = hostport.substr(0, colon);
        int pn = std::atoi(hostport.substr(colon + 1).c_str());
        if (pn > 0 && pn <= 65535) p.port = pn;
    } else {
        p.host = hostport;
    }
    p.ok = !p.host.empty();
    return p;
}

// RFC 7230 chunked transfer decoding. tolerant of truncation.
string dechunk(const string& b) {
    string out;
    size_t i = 0, n = b.size();
    while (i < n) {
        size_t eol = b.find("\r\n", i);
        if (eol == string::npos) break;
        string sizeline = b.substr(i, eol - i);
        size_t semi = sizeline.find(';');          // strip chunk extensions
        if (semi != string::npos) sizeline.resize(semi);
        unsigned long csize = std::strtoul(sizeline.c_str(), nullptr, 16);
        i = eol + 2;
        if (csize == 0) break;                      // terminating chunk
        if (i + csize > n) csize = n - i;           // truncated body
        out.append(b, i, csize);
        i += csize;
        if (i + 2 <= n && b[i] == '\r' && b[i + 1] == '\n') i += 2;
    }
    return out;
}

// read the whole plaintext response off a connected, blocking socket.
string read_all_plain(SOCKET s) {
    string raw; char buf[16384];
    for (;;) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, (size_t)n);
        if (raw.size() > 2u * 1024 * 1024) break;
    }
    return raw;
}

string read_all_tls(SSL* ssl) {
    string raw; char buf[16384];
    for (;;) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;                          // clean close or timeout
        raw.append(buf, (size_t)n);
        if (raw.size() > 2u * 1024 * 1024) break;
    }
    return raw;
}

// GET over TLS with full certificate + hostname verification (parity with
// WinHTTP's default secure posture). returns raw response or "" on failure,
// with err set.
string https_exchange(SOCKET s, const string& host, const string& req, string& err) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { err = "ctx"; return ""; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        // no system trust store — fail closed rather than silently skip verify.
        err = "no-ca"; SSL_CTX_free(ctx); return "";
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { err = "ssl"; SSL_CTX_free(ctx); return ""; }
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, host.c_str());     // SNI
    X509_VERIFY_PARAM* vp = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(vp, host.c_str(), 0);

    string raw;
    if (SSL_connect(ssl) != 1) {
        err = "tls";
    } else {
        SSL_write(ssl, req.data(), (int)req.size());
        raw = read_all_tls(ssl);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return raw;
}

} // namespace

HttpResp http_get(const string& url, int timeout_ms, const string& accept) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    auto finish = [&](const char* e) -> HttpResp {
        if (e) r.err = e;
        r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - t0).count();
        return r;
    };

    ParsedUrl p = parse_url(url);
    if (!p.ok) return finish("bad url");

    string err;
    SOCKET s = tcp_connect(p.host, p.port, timeout_ms, err);
    if (s == INVALID_SOCKET) return finish(err.empty() ? "connect" : err.c_str());
    sock_set_recv_timeout(s, timeout_ms);

    // bare GET, no UA — mirrors the WinHTTP empty-UA on-the-wire posture. no
    // Accept-Encoding, so servers reply identity-coded (no gzip to inflate).
    string req = "GET " + p.path + " HTTP/1.1\r\n"
                 "Host: " + p.host + "\r\n"
                 "Connection: close\r\n";
    if (!accept.empty()) req += "Accept: " + accept + "\r\n";
    req += "\r\n";

    string raw;
    if (p.https) {
        raw = https_exchange(s, p.host, req, err);
        closesocket(s);
        if (raw.empty()) return finish(err.empty() ? "tls" : err.c_str());
    } else {
        tcp_send_all(s, req.data(), (int)req.size());
        raw = read_all_plain(s);
        closesocket(s);
    }

    size_t hdr_end = raw.find("\r\n\r\n");
    if (hdr_end == string::npos) return finish("proto");
    string head = raw.substr(0, hdr_end);
    string body = raw.substr(hdr_end + 4);

    size_t sp = head.find(' ');                      // "HTTP/1.1 200 OK"
    if (sp != string::npos) r.status = std::atoi(head.c_str() + sp + 1);

    string lchead = tolower_s(head);
    if (lchead.find("transfer-encoding:") != string::npos &&
        lchead.find("chunked") != string::npos)
        body = dechunk(body);

    if (body.size() > 512 * 1024) body.resize(512 * 1024);
    r.body = std::move(body);
    return finish(nullptr);
}

#endif // _WIN32
