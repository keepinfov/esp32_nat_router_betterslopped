/* Web interface (HTTP server)
 *
 * Pages:
 *   /          - Status dashboard: connection state, clients, heap, uptime, login
 *   /config    - Router configuration: AP/STA settings, static IP, MAC addresses
 *   /mappings  - DHCP reservations and port forwarding management
 *   /firewall  - ACL firewall rules (4 lists, add/delete, hit statistics)
 *   /vpn       - WireGuard VPN configuration and status
 *   /scan      - WiFi network scanner (STA uplink only)
 *
 * Password-protected pages use cookie-based sessions (30-min timeout).
 * HTML templates are defined in pages.h as C macro strings.
 */
#include "esp_netif.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <sys/param.h>
#include "nvs_flash.h"
#include "esp_netif.h"
//#include "esp_eth.h"
//#include "protocol_examples_common.h"

#include <esp_http_server.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/lwip_napt.h"
#include "lwip/sockets.h"

#include "pages.h"
#include "router_globals.h"
#include "vpn_config.h"
#include "pcap_capture.h"
#include "acl.h"
#include "remote_console.h"
#include "cJSON.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"

static const char *TAG = "HTTPServer";

/* Stream one HTTP chunk and abort the handler immediately if the send fails.
 *
 * httpd_resp_send_chunk() blocks up to config.send_wait_timeout when the client
 * is gone or its TCP window is full.  The page handlers issue dozens of chunks
 * in sequence; without checking the result, a dead client makes the handler
 * spin through every remaining chunk (one timeout each), wedging the single
 * httpd worker and pinning that connection's buffers/socket.
 *
 * Returning ESP_FAIL on the first failed chunk lets httpd tear the connection
 * down at once.  Handlers that stream with SEND_CHUNK must NOT hold a heap
 * allocation across the chunk loop: a bail-out returns immediately and would
 * leak it.  Render from a stack buffer, or free before streaming begins. */
#define SEND_CHUNK(req, ...) \
    do { \
        if (httpd_resp_send_chunk((req), __VA_ARGS__) != ESP_OK) { \
            return ESP_FAIL; \
        } \
    } while (0)

/* Stream a section that was just rendered into a stack buffer.
 *
 * snprintf() returns the length it *wanted* to write, not the length it wrote.
 * Passing that straight to httpd_resp_send_chunk() would hand it a length past
 * the end of the buffer the moment a section truncates — an escaped SSID and an
 * escaped hostname in the same form are enough to get close.  Clamping here
 * means the worst case is a short page, not a read out of bounds.
 *
 * buf must be an array, not a pointer: the clamp is sizeof(buf). */
#define SEND_RENDERED(req, buf, len) \
    SEND_CHUNK((req), (buf), \
               (len) < (int)sizeof(buf) ? (len) : (int)sizeof(buf) - 1)

/* Escape src into a fixed stack buffer (truncating if needed) and free the
 * heap copy from html_escape().  Page handlers use this so they never hold an
 * html_escape() allocation across a chunked SEND_CHUNK render. */
char* html_escape(const char* src);
static void html_escape_to(char *dst, size_t dst_len, const char *src)
{
    char *e = html_escape(src ? src : "");
    strlcpy(dst, e ? e : "", dst_len);
    free(e);
}

/* Get client IP address string from HTTP request */
static const char *get_client_ip(httpd_req_t *req, char *buf, size_t buf_len)
{
    int sockfd = httpd_req_to_sockfd(req);
    struct sockaddr_in6 addr6;
    socklen_t addr_len = sizeof(addr6);
    if (getpeername(sockfd, (struct sockaddr *)&addr6, &addr_len) == 0) {
        /* ESP-IDF httpd uses IPv6 sockets; IPv4 clients appear as
         * ::ffff:x.x.x.x (IPv4-mapped IPv6).  Extract the IPv4 part. */
        if (addr6.sin6_family == AF_INET6) {
            struct in_addr ipv4;
            memcpy(&ipv4, addr6.sin6_addr.s6_addr + 12, 4);
            inet_ntoa_r(ipv4, buf, buf_len);
        } else {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr6;
            inet_ntoa_r(addr4->sin_addr, buf, buf_len);
        }
    } else {
        strncpy(buf, "unknown", buf_len);
    }
    return buf;
}

/* Web UI interface access bitmask (RC_BIND_AP, RC_BIND_STA, RC_BIND_VPN).
 * Loaded from NVS in start_webserver(). Default: all interfaces allowed. */
static uint8_t s_web_bind = RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN;

/* Check whether an incoming HTTP connection is allowed based on which
 * network interface it arrived on.  Called by esp_http_server before any
 * data is exchanged; returning ESP_FAIL closes the socket immediately.
 *
 * getsockname() on the accepted socket returns the local IP that was used
 * by the client — i.e. the address of the interface the packet arrived on.
 * esp_http_server uses IPv6 sockets, so IPv4 connections appear as
 * ::ffff:x.x.x.x (IPv4-mapped).  The same extraction used in get_client_ip()
 * is applied here for the local side.
 */
static esp_err_t http_open_fn(httpd_handle_t hd, int sockfd)
{
    /* Enable TCP keepalive on every accepted connection.  A client that leaves
     * WiFi without closing leaves the socket in ESTABLISHED forever; without
     * probes lwIP never notices and the socket (and its few KB of buffers) leaks
     * until the table fills.  With keepalive the dead peer is detected and the
     * socket torn down automatically.  ~30 s idle, then 3 probes 5 s apart. */
    int ka = 1, ka_idle = 30, ka_intvl = 5, ka_cnt = 3;
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intvl, sizeof(ka_intvl));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));

    struct sockaddr_in6 local_addr6;
    socklen_t addr_len = sizeof(local_addr6);
    uint32_t local_ip = 0;  /* network byte order */

    if (getsockname(sockfd, (struct sockaddr *)&local_addr6, &addr_len) == 0) {
        if (local_addr6.sin6_family == AF_INET6) {
            /* IPv4-mapped IPv6: last 4 bytes of s6_addr are the IPv4 address */
            memcpy(&local_ip, local_addr6.sin6_addr.s6_addr + 12, 4);
        } else {
            local_ip = ((struct sockaddr_in *)&local_addr6)->sin_addr.s_addr;
        }
    }

    /* Identify which interface the connection arrived on */
    bool on_ap  = (local_ip != 0 && local_ip == my_ap_ip);
    bool on_sta = (local_ip != 0 && local_ip == my_ip);
    bool on_vpn = false;
    if (local_ip != 0 && vpn_connected && vpn_address && vpn_address[0]) {
        ip4_addr_t vpn_addr;
        if (ip4addr_aton(vpn_address, &vpn_addr) && local_ip == vpn_addr.addr) {
            on_vpn = true;
        }
    }

    /* Enforce interface access policy */
    bool allowed = false;
    if (on_ap  && (s_web_bind & RC_BIND_AP))  allowed = true;
    if (on_sta && (s_web_bind & RC_BIND_STA)) allowed = true;
    if (on_vpn && (s_web_bind & RC_BIND_VPN)) allowed = true;

    /* An unknown local address used to be allowed through, which turned the
     * whole interface restriction into a suggestion. getsockname() does not
     * fail on an accepted socket in practice; if it ever does, refusing is the
     * only answer that keeps the setting meaningful. Serial console recovery
     * (web_ui bind all) is documented for the lockout case either way. */
    if (local_ip == 0) {
        ESP_LOGW(TAG, "HTTP connection rejected (local address unknown)");
        return ESP_FAIL;
    }

    if (!allowed) {
        ESP_LOGW(TAG, "HTTP connection rejected (interface not allowed, local=" IPSTR ")",
                 IP2STR((ip4_addr_t *)&local_ip));
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void web_server_start_captive_dns(void);

esp_timer_handle_t restart_timer;

/* Session management for password protection */
#define MAX_SESSION_TOKEN_LEN 32
#define SESSION_TIMEOUT_US (30 * 60 * 1000000LL) // 30 minutes

static char current_session_token[MAX_SESSION_TOKEN_LEN + 1] = {0};
static bool session_active = false;
static int64_t session_expiry_time = 0;

static void restart_timer_callback(void* arg)
{
    ESP_LOGI(TAG, "Restarting now...");
    esp_restart();
}

esp_timer_create_args_t restart_timer_args = {
        .callback = &restart_timer_callback,
        /* argument specified here will be passed to timer callback function */
        .arg = (void*) 0,
        .name = "restart_timer"
};

/* Session management helper functions */

/* Generate random session token */
static void generate_session_token(char* token_out, size_t len)
{
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        token_out[i] = hex_chars[esp_random() % 16];
    }
    token_out[len - 1] = '\0';
}

/* Clear session state */
static void clear_session(void)
{
    session_active = false;
    current_session_token[0] = '\0';
    session_expiry_time = 0;
}

/* Password checking uses shared functions from router_globals.h:
 * is_web_password_set(), verify_web_password(), set_web_password_hashed() */

/* Extract cookie value from request headers */
static bool get_cookie_value(httpd_req_t *req, const char* cookie_name,
                              char* value_out, size_t max_len)
{
    size_t cookie_header_len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (cookie_header_len == 0) {
        return false;
    }

    char* cookie_header = malloc(cookie_header_len + 1);
    if (cookie_header == NULL) {
        return false;
    }

    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_header, cookie_header_len + 1) != ESP_OK) {
        free(cookie_header);
        return false;
    }

    /* Match the name only at a cookie boundary — a plain strstr() for
     * "session=" also matches a cookie called "xsession", letting a caller
     * supply the value the check is meant to verify. */
    char search_pattern[64];
    snprintf(search_pattern, sizeof(search_pattern), "%s=", cookie_name);
    size_t pattern_len = strlen(search_pattern);

    char* cookie_start = NULL;
    for (char* p = cookie_header; (p = strstr(p, search_pattern)) != NULL; p += pattern_len) {
        bool at_boundary = (p == cookie_header) ||
                           (p[-1] == ';') ||
                           (p[-1] == ' ' && p >= cookie_header + 2 && p[-2] == ';');
        if (at_boundary) {
            cookie_start = p + pattern_len;
            break;
        }
    }

    if (cookie_start == NULL) {
        free(cookie_header);
        return false;
    }

    // Find the end of the cookie value (semicolon or end of string)
    char* cookie_end = strchr(cookie_start, ';');
    size_t cookie_len = cookie_end ? (size_t)(cookie_end - cookie_start) : strlen(cookie_start);

    if (cookie_len >= max_len) {
        cookie_len = max_len - 1;
    }

    strncpy(value_out, cookie_start, cookie_len);
    value_out[cookie_len] = '\0';

    free(cookie_header);
    return true;
}

/* Check if request has valid session cookie */
/* CSRF check: if the browser sends an Origin header it must match one of our
 * own IP addresses (AP or STA).  Requests without Origin (curl, API clients)
 * are allowed through.
 * Returns true if the request is safe to process. */
static bool check_csrf(httpd_req_t *req)
{
    char origin[64];
    if (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) != ESP_OK) {
        return true;  /* No Origin — non-browser or same-origin fetch, allow */
    }
    /* Same-origin check: the Origin host[:port] must equal the Host header the
     * browser used to reach us. This covers access by mDNS hostname
     * (e.g. http://esp32.local) or a non-default port, which the IP checks below
     * would miss. A cross-site attacker's Origin won't match our Host, so it's
     * still rejected. */
    char host[64];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_OK) {
        char expected_host[72];
        snprintf(expected_host, sizeof(expected_host), "http://%s", host);
        if (strcmp(origin, expected_host) == 0) return true;
    }

    char expected[32];
    ip4_addr_t addr;

    /* Accept requests originating from the AP interface */
    addr.addr = my_ap_ip;
    snprintf(expected, sizeof(expected), "http://" IPSTR, IP2STR(&addr));
    if (strcmp(origin, expected) == 0) return true;

    /* Also accept requests originating from the STA interface */
    if (my_ip != 0) {
        addr.addr = my_ip;
        snprintf(expected, sizeof(expected), "http://" IPSTR, IP2STR(&addr));
        if (strcmp(origin, expected) == 0) return true;
    }

    /* Also accept requests originating from the VPN/WireGuard interface */
    if (vpn_tunnel_ip != 0) {
        addr.addr = vpn_tunnel_ip;
        snprintf(expected, sizeof(expected), "http://" IPSTR, IP2STR(&addr));
        if (strcmp(origin, expected) == 0) return true;
    }

    return false;
}

/* Pull the "error" parameter out of a request's query string, URL-decoded far
 * enough to read and HTML-escaped for the page.
 *
 * A rejected form redirects back to its own page carrying the reason, so the
 * reason arrives on a GET even though the change itself was a POST.  It is
 * attacker-supplied by construction — anyone can hand an administrator a link
 * with any text in it — which is why it is escaped rather than trusted. */
static void read_error_param(httpd_req_t *req, char *out, size_t out_len)
{
    out[0] = '\0';
    size_t qlen = httpd_req_get_url_query_len(req) + 1;
    if (qlen <= 1) {
        return;
    }
    char *q = malloc(qlen);
    if (q == NULL) {
        return;
    }
    char raw[128];
    if (httpd_req_get_url_query_str(req, q, qlen) == ESP_OK &&
        httpd_query_key_value(q, "error", raw, sizeof(raw)) == ESP_OK) {
        for (char *p = raw; *p; p++) {
            if (*p == '+') *p = ' ';
        }
        html_escape_to(out, out_len, raw);
    }
    free(q);
}

/* Read an application/x-www-form-urlencoded body into a heap buffer.
 *
 * A form body has exactly the syntax of a query string, so httpd_query_key_value()
 * reads keys straight out of it — which is why moving the settings pages from GET
 * to POST left their parsing untouched.
 *
 * Returns NULL for an absent, oversized or truncated body; the caller frees. */
#define MAX_FORM_BODY 2048

static char *read_form_body(httpd_req_t *req)
{
    if (req->content_len == 0 || req->content_len > MAX_FORM_BODY) {
        return NULL;
    }
    char *body = malloc(req->content_len + 1);
    if (body == NULL) {
        return NULL;
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        /* recv_wait_timeout is two seconds and these bodies are a few hundred
         * bytes on a local link, so a short read means the client is gone. */
        if (r <= 0) {
            free(body);
            return NULL;
        }
        got += (size_t)r;
    }
    body[got] = '\0';
    return body;
}

/* Accept a settings change, or answer the request and tell the caller to stop.
 *
 * Settings used to change on GET, which means any page the administrator
 * happens to be visiting can change them: the browser attaches the session
 * cookie to a cross-site <img src="http://192.168.4.1/config?reset=1"> without
 * asking, and there is no Origin header on such a request to reject it by.
 * A form POST always carries Origin, so check_csrf() has something to check.
 *
 * On a GET this returns true with *form NULL — the page renders, nothing
 * changes.  On a POST it returns true with *form holding the body, or false
 * having already sent the error response. */
static bool take_form(httpd_req_t *req, char **form)
{
    *form = NULL;
    if (req->method != HTTP_POST) {
        return true;
    }
    if (!check_csrf(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "CSRF rejected %s from %s", req->uri,
                                 get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Cross-site request rejected");
        return false;
    }
    *form = read_form_body(req);
    if (*form == NULL) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Unreadable form data");
        return false;
    }
    return true;
}

/* Check if request has valid session cookie */
static bool is_authenticated(httpd_req_t *req)
{
    // If no session is active, not authenticated
    if (!session_active) {
        return false;
    }

    // Check if session has expired
    int64_t current_time = esp_timer_get_time();
    if (current_time > session_expiry_time) {
        clear_session();
        return false;
    }

    // Extract session cookie
    char session_token[MAX_SESSION_TOKEN_LEN + 1];
    if (!get_cookie_value(req, "session", session_token, sizeof(session_token))) {
        return false;
    }

    /* Constant-time compare: strcmp() returns as soon as two bytes differ, so
     * response timing leaks how much of the token a guess got right. */
    size_t expected_len = strlen(current_session_token);
    if (strlen(session_token) != expected_len) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < expected_len; i++) {
        diff |= (uint8_t)(session_token[i] ^ current_session_token[i]);
    }
    if (diff != 0) {
        return false;
    }

    // Extend session expiry on successful auth
    session_expiry_time = current_time + SESSION_TIMEOUT_US;

    return true;
}

/* Cookie header buffer - must be static because httpd_resp_set_hdr stores pointer, not copy */
static char session_cookie_header[128];

/* Create new session and set cookie */
static esp_err_t create_session(httpd_req_t *req)
{
    // Generate new session token
    generate_session_token(current_session_token, sizeof(current_session_token));

    // Set session active and expiry
    session_active = true;
    session_expiry_time = esp_timer_get_time() + SESSION_TIMEOUT_US;

    // Set cookie in response (using static buffer because httpd stores pointer)
    /* Max-Age makes this a persistent cookie (matching SESSION_TIMEOUT_US) so it
     * survives page reloads and the iOS captive-portal browser, which discards
     * session-only cookies aggressively. */
    /* HttpOnly keeps the token out of document.cookie, so an XSS bug on any
     * page cannot hand the session to an attacker. Nothing here reads the
     * cookie from JavaScript. */
    snprintf(session_cookie_header, sizeof(session_cookie_header),
             "session=%s; Path=/; Max-Age=1800; SameSite=Strict; HttpOnly", current_session_token);
    httpd_resp_set_hdr(req, "Set-Cookie", session_cookie_header);

    ESP_LOGI(TAG, "Session created, expires in 30 minutes");
    return ESP_OK;
}

/* --- Config Export/Import helpers --- */

/*
 * Encrypted config file format (JSON envelope):
 *   {"enc":1,"s":"<hex 16-byte salt>","n":"<hex 24-byte nonce>","c":"<base64 ciphertext>"}
 *
 * Key derivation : PBKDF2-HMAC-SHA256, 10 000 iterations, 32-byte output
 * Encryption     : XChaCha20-Poly1305 AEAD (24-byte nonce, 16-byte auth tag)
 *
 * The XChaCha20-Poly1305 implementation is the one bundled with the WireGuard
 * managed component; the symbols are already compiled into the binary.
 */

/* Forward-declare XChaCha20-Poly1305 from managed_components/esp_wireguard */
extern void xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *nonce, const uint8_t *key);
extern bool xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *nonce, const uint8_t *key);

#define ENC_SALT_LEN    16
#define ENC_NONCE_LEN   24
#define ENC_KEY_LEN     32
#define ENC_TAG_LEN     16
#define ENC_PBKDF2_ITER 10000

/* Encrypted payload is larger than the raw JSON: base64(plaintext + 16 tag)
 * plus the JSON envelope headers (~100 bytes).
 * Max plaintext 8 192 B → cipher 8 208 B → base64 ~10 944 B → total ~11 100 B.
 * Use 16 384 as the import limit to cover both plain and encrypted files. */
#define CONFIG_IMPORT_MAX_SIZE 16384

static char *bytes_to_hex(const uint8_t *src, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", src[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static int hex_to_bytes(const char *src, uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(src + i * 2, "%2x", &byte) != 1) return -1;
        dst[i] = (uint8_t)byte;
    }
    return 0;
}

/* Derive a 32-byte key from passphrase + salt using PBKDF2-HMAC-SHA256. */
static void config_derive_key(const char *pass, const uint8_t *salt, uint8_t key[ENC_KEY_LEN])
{
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                  (const uint8_t *)pass, strlen(pass),
                                  salt, ENC_SALT_LEN,
                                  ENC_PBKDF2_ITER,
                                  ENC_KEY_LEN, key);
}

/*
 * Encrypt plain JSON string with the given passphrase.
 * Returns a malloc'd JSON envelope string, or NULL on allocation failure.
 */
/*
 * Encrypt plaintext JSON into a JSON envelope.
 * Takes ownership of `plain` (frees it) to reduce peak heap usage —
 * the caller must NOT free plain after this call.
 */
static char *config_encrypt_json(char *plain, size_t plain_len, const char *pass)
{
    uint8_t salt[ENC_SALT_LEN], nonce[ENC_NONCE_LEN], key[ENC_KEY_LEN];
    esp_fill_random(salt, sizeof(salt));
    esp_fill_random(nonce, sizeof(nonce));
    config_derive_key(pass, salt, key);

    size_t cipher_len = plain_len + ENC_TAG_LEN;
    uint8_t *cipher = malloc(cipher_len);
    if (!cipher) { free(plain); return NULL; }
    xchacha20poly1305_encrypt(cipher, (const uint8_t *)plain, plain_len,
                              NULL, 0, nonce, key);
    free(plain); /* Release early — no longer needed after encryption */

    /* Hex-encode salt and nonce */
    char salt_hex[ENC_SALT_LEN * 2 + 1];
    char nonce_hex[ENC_NONCE_LEN * 2 + 1];
    for (int i = 0; i < ENC_SALT_LEN; i++)  sprintf(salt_hex  + i*2, "%02x", salt[i]);
    for (int i = 0; i < ENC_NONCE_LEN; i++) sprintf(nonce_hex + i*2, "%02x", nonce[i]);
    salt_hex[ENC_SALT_LEN * 2]   = '\0';
    nonce_hex[ENC_NONCE_LEN * 2] = '\0';

    /* Query base64 output size (b64_needed includes trailing NUL) */
    size_t b64_needed = 0;
    mbedtls_base64_encode(NULL, 0, &b64_needed, cipher, cipher_len);
    size_t b64_str_len = b64_needed > 0 ? b64_needed - 1 : 0;

    /* Build JSON prefix and suffix so we can base64-encode directly into
     * the output buffer, avoiding a separate b64 allocation. */
    size_t pre_len = (size_t)snprintf(NULL, 0,
                        "{\"enc\":1,\"s\":\"%s\",\"n\":\"%s\",\"c\":\"",
                        salt_hex, nonce_hex);
    size_t out_len = pre_len + b64_str_len + 2 + 1; /* 2 for "}, 1 for NUL */
    char *out = malloc(out_len);
    if (!out) { free(cipher); return NULL; }

    /* Write JSON prefix */
    snprintf(out, pre_len + 1,
             "{\"enc\":1,\"s\":\"%s\",\"n\":\"%s\",\"c\":\"",
             salt_hex, nonce_hex);

    /* Base64-encode ciphertext directly into the output buffer */
    size_t b64_written = 0;
    mbedtls_base64_encode((unsigned char *)(out + pre_len),
                          out_len - pre_len, &b64_written,
                          cipher, cipher_len);
    free(cipher);

    /* Close the JSON envelope (overwrite the base64 NUL terminator) */
    memcpy(out + pre_len + b64_written, "\"}", 3); /* includes NUL */
    return out;
}

/*
 * Decrypt an envelope produced by config_encrypt_json().
 * Returns a malloc'd null-terminated plaintext string, or NULL on failure
 * (wrong passphrase or corrupt data → authentication tag mismatch).
 */
static char *config_decrypt_json(const char *enc_json, const char *pass)
{
    cJSON *j = cJSON_Parse(enc_json);
    if (!j) return NULL;

    cJSON *s_item = cJSON_GetObjectItem(j, "s");
    cJSON *n_item = cJSON_GetObjectItem(j, "n");
    cJSON *c_item = cJSON_GetObjectItem(j, "c");
    if (!cJSON_IsString(s_item) || !cJSON_IsString(n_item) || !cJSON_IsString(c_item)) {
        cJSON_Delete(j); return NULL;
    }

    uint8_t salt[ENC_SALT_LEN], nonce[ENC_NONCE_LEN];
    if (hex_to_bytes(s_item->valuestring, salt,  ENC_SALT_LEN)  != 0 ||
        hex_to_bytes(n_item->valuestring, nonce, ENC_NONCE_LEN) != 0) {
        cJSON_Delete(j); return NULL;
    }

    /* Base64-decode ciphertext */
    size_t b64_in_len = strlen(c_item->valuestring);
    size_t cipher_len = 0;
    mbedtls_base64_decode(NULL, 0, &cipher_len,
                          (const unsigned char *)c_item->valuestring, b64_in_len);
    uint8_t *cipher = malloc(cipher_len);
    if (!cipher) { cJSON_Delete(j); return NULL; }
    size_t actual_cipher_len = 0;
    int rc = mbedtls_base64_decode(cipher, cipher_len, &actual_cipher_len,
                                   (const unsigned char *)c_item->valuestring, b64_in_len);
    cJSON_Delete(j);
    if (rc != 0 || actual_cipher_len < ENC_TAG_LEN) { free(cipher); return NULL; }

    uint8_t key[ENC_KEY_LEN];
    config_derive_key(pass, salt, key);

    size_t plain_len = actual_cipher_len - ENC_TAG_LEN;
    uint8_t *plain = malloc(plain_len + 1);
    if (!plain) { free(cipher); return NULL; }

    bool ok = xchacha20poly1305_decrypt(plain, cipher, actual_cipher_len,
                                        NULL, 0, nonce, key);
    free(cipher);
    if (!ok) { free(plain); return NULL; }  /* wrong passphrase / tampered data */

    plain[plain_len] = '\0';
    return (char *)plain;
}

/* include_secrets: if false, WireGuard private key and PSK are omitted (plain-text export).
 *                  if true,  all keys are included (encrypted export only). */
static char *nvs_export_to_json_robust(bool include_secrets)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return NULL;

    cJSON *arr = cJSON_CreateArray();
    if (!arr) { nvs_close(nvs); return NULL; }

    nvs_iterator_t it = NULL;
    err = nvs_entry_find_in_handle(nvs, NVS_TYPE_ANY, &it);
    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        /* Skip secrets for plain (unencrypted) exports:
         *   passwd       — STA WiFi password (also used as WPA-Enterprise EAP password)
         *   ap_passwd    — AP WiFi password
         *   vpn_privkey  — WireGuard private key
         *   vpn_psk      — WireGuard pre-shared key
         *   web_password — salt:hash of the web UI password. Exporting it put
         *                  the hash in a plaintext file anyone could take away
         *                  and grind offline.
         *   mqtt_pass    — MQTT broker credential */
        if (!include_secrets &&
            (strcmp(info.key, "passwd")       == 0 ||
             strcmp(info.key, "ap_passwd")    == 0 ||
             strcmp(info.key, "vpn_privkey")  == 0 ||
             strcmp(info.key, "vpn_psk")      == 0 ||
             strcmp(info.key, "web_password") == 0 ||
             strcmp(info.key, "mqtt_pass")    == 0)) {
            err = nvs_entry_next(&it);
            continue;
        }

        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "key", info.key);
        cJSON_AddNumberToObject(item, "type", info.type);

        switch (info.type) {
            case NVS_TYPE_U8: {
                uint8_t v; nvs_get_u8(nvs, info.key, &v);
                cJSON_AddNumberToObject(item, "val", v);
                break;
            }
            case NVS_TYPE_U16: {
                uint16_t v; nvs_get_u16(nvs, info.key, &v);
                cJSON_AddNumberToObject(item, "val", v);
                break;
            }
            case NVS_TYPE_U32: {
                uint32_t v; nvs_get_u32(nvs, info.key, &v);
                cJSON_AddNumberToObject(item, "val", v);
                break;
            }
            case NVS_TYPE_I32: {
                int32_t v; nvs_get_i32(nvs, info.key, &v);
                cJSON_AddNumberToObject(item, "val", v);
                break;
            }
            case NVS_TYPE_STR: {
                size_t len = 0;
                nvs_get_str(nvs, info.key, NULL, &len);
                char *buf = malloc(len);
                if (buf) {
                    nvs_get_str(nvs, info.key, buf, &len);
                    cJSON_AddStringToObject(item, "val", buf);
                    free(buf);
                }
                break;
            }
            case NVS_TYPE_BLOB: {
                size_t len = 0;
                nvs_get_blob(nvs, info.key, NULL, &len);
                uint8_t *buf = malloc(len);
                if (buf) {
                    nvs_get_blob(nvs, info.key, buf, &len);
                    char *hex = bytes_to_hex(buf, len);
                    free(buf);
                    if (hex) {
                        cJSON_AddStringToObject(item, "val", hex);
                        free(hex);
                    }
                }
                break;
            }
            default:
                break;
        }
        cJSON_AddItemToArray(arr, item);
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    nvs_close(nvs);

    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}

static esp_err_t nvs_import_from_json_robust(const char *json_str)
{
    cJSON *arr = cJSON_Parse(json_str);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return ESP_ERR_INVALID_ARG;
    }

    /* Validate all entries before touching NVS */
    int valid_count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        cJSON *jkey = cJSON_GetObjectItem(item, "key");
        cJSON *jtype = cJSON_GetObjectItem(item, "type");
        cJSON *jval = cJSON_GetObjectItem(item, "val");
        if (!jkey || !cJSON_IsString(jkey) || !jtype || !cJSON_IsNumber(jtype) || !jval) continue;
        valid_count++;
    }
    if (valid_count == 0) {
        cJSON_Delete(arr);
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) { cJSON_Delete(arr); return err; }

    /* Erase all existing keys — safe now that JSON is validated */
    nvs_erase_all(nvs);

    cJSON_ArrayForEach(item, arr) {
        cJSON *jkey = cJSON_GetObjectItem(item, "key");
        cJSON *jtype = cJSON_GetObjectItem(item, "type");
        cJSON *jval = cJSON_GetObjectItem(item, "val");
        if (!jkey || !cJSON_IsString(jkey) || !jtype || !cJSON_IsNumber(jtype) || !jval) continue;

        const char *key = jkey->valuestring;
        int type = (int)jtype->valuedouble;

        switch (type) {
            case NVS_TYPE_U8:
                if (cJSON_IsNumber(jval)) nvs_set_u8(nvs, key, (uint8_t)jval->valuedouble);
                break;
            case NVS_TYPE_U16:
                if (cJSON_IsNumber(jval)) nvs_set_u16(nvs, key, (uint16_t)jval->valuedouble);
                break;
            case NVS_TYPE_U32:
                if (cJSON_IsNumber(jval)) nvs_set_u32(nvs, key, (uint32_t)jval->valuedouble);
                break;
            case NVS_TYPE_I32:
                if (cJSON_IsNumber(jval)) nvs_set_i32(nvs, key, (int32_t)jval->valuedouble);
                break;
            case NVS_TYPE_STR:
                if (cJSON_IsString(jval)) nvs_set_str(nvs, key, jval->valuestring);
                break;
            case NVS_TYPE_BLOB: {
                if (!cJSON_IsString(jval)) break;
                size_t hex_len = strlen(jval->valuestring);
                if (hex_len % 2 != 0) break;
                size_t blob_len = hex_len / 2;
                uint8_t *blob = malloc(blob_len);
                if (blob) {
                    if (hex_to_bytes(jval->valuestring, blob, blob_len) == 0) {
                        nvs_set_blob(nvs, key, blob, blob_len);
                    }
                    free(blob);
                }
                break;
            }
            default:
                break;
        }
    }

    nvs_commit(nvs);
    nvs_close(nvs);
    cJSON_Delete(arr);
    return ESP_OK;
}

/* Resume STA connection attempts if a WiFi scan had suppressed them.
 * Called from non-scan page handlers so that navigating away from /scan
 * (or any other page load) restarts the connection process. */
static inline void resume_sta_if_scan_idle(void)
{
    if (wifi_scan_active) {
        wifi_scan_active = false;
        if (!ap_connect) {
            esp_wifi_connect();
        }
    }
}

/* --- Config Export/Import HTTP handlers --- */

static esp_err_t config_export_handler(httpd_req_t *req)
{
    if (!check_csrf(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "CSRF rejected /api/config-export from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "CSRF check failed");
        return ESP_FAIL;
    }
    bool password_protection_enabled = is_web_password_set();
    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /api/config-export from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not authenticated");
        return ESP_FAIL;
    }

    /* Read optional passphrase from POST JSON body: {"pass":"..."} */
    char pass[128] = {0};
    if (req->content_len > 0 && req->content_len < 256) {
        char body[256];
        int recv_len = httpd_req_recv(req, body, req->content_len);
        if (recv_len > 0) {
            body[recv_len] = '\0';
            cJSON *j = cJSON_Parse(body);
            if (j) {
                cJSON *p = cJSON_GetObjectItem(j, "pass");
                if (cJSON_IsString(p) && p->valuestring[0] != '\0') {
                    strlcpy(pass, p->valuestring, sizeof(pass));
                }
                cJSON_Delete(j);
            }
        }
    }

    /* Include WireGuard secrets only in encrypted exports */
    char *plain = nvs_export_to_json_robust(pass[0] != '\0');
    if (!plain) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Export failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"esp32_nat_config.json\"");

    if (pass[0] == '\0') {
        /* No passphrase — send plain JSON (WireGuard secrets already omitted) */
        httpd_resp_send(req, plain, HTTPD_RESP_USE_STRLEN);
        free(plain);
    } else {
        /* Encrypt with PBKDF2-derived XChaCha20-Poly1305 key
         * config_encrypt_json() takes ownership of plain and frees it. */
        char *enc = config_encrypt_json(plain, strlen(plain), pass);
        if (!enc) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Encryption failed");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Config exported (encrypted)");
        httpd_resp_send(req, enc, HTTPD_RESP_USE_STRLEN);
        free(enc);
    }
    return ESP_OK;
}

static esp_err_t config_import_handler(httpd_req_t *req)
{
    if (!check_csrf(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "CSRF rejected /api/config-import from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "CSRF check failed");
        return ESP_FAIL;
    }
    bool password_protection_enabled = is_web_password_set();
    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /api/config-import from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not authenticated");
        return ESP_FAIL;
    }

    if (req->content_len > CONFIG_IMPORT_MAX_SIZE || req->content_len == 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Invalid body size\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char *body = malloc(req->content_len + 1);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }

    int total = 0;
    while (total < req->content_len) {
        int ret = httpd_req_recv(req, body + total, req->content_len - total);
        if (ret <= 0) {
            free(body);
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            return ESP_FAIL;
        }
        total += ret;
    }
    body[total] = '\0';

    /* Detect encrypted envelope with a cheap string search instead of
     * parsing the entire JSON — saves a full cJSON tree allocation. */
    char *json_to_import = body;
    char *decrypted = NULL;
    bool is_encrypted = (strstr(body, "\"enc\"") != NULL &&
                         strstr(body, "\"c\"")   != NULL);

    if (is_encrypted) {
        /* Read passphrase from X-Config-Pass header */
        char pass[128] = {0};
        httpd_req_get_hdr_value_str(req, "X-Config-Pass", pass, sizeof(pass));

        if (pass[0] == '\0') {
            free(body);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Encrypted config requires passphrase\"}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }

        decrypted = config_decrypt_json(body, pass);
        if (!decrypted) {
            free(body);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Decryption failed: wrong passphrase or corrupt file\"}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }
        ESP_LOGI(TAG, "Config import: decryption OK");
        free(body);          /* Release early — no longer needed after decryption */
        body = NULL;
        json_to_import = decrypted;
    }

    esp_err_t err = nvs_import_from_json_robust(json_to_import);
    free(body);              /* NULL-safe: no-op if already freed above */
    if (decrypted) free(decrypted);

    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        httpd_resp_send(req, "{\"ok\":true,\"msg\":\"Config imported. Rebooting...\"}", HTTPD_RESP_USE_STRLEN);
        esp_timer_start_once(restart_timer, 3000000);
    } else {
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Import failed: invalid JSON\"}", HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

static httpd_uri_t config_exportp = {
    .uri       = "/api/config-export",
    .method    = HTTP_POST,
    .handler   = config_export_handler,
};

static httpd_uri_t config_importp = {
    .uri       = "/api/config-import",
    .method    = HTTP_POST,
    .handler   = config_import_handler,
};

/* --- WireGuard .conf import handler --- */

static esp_err_t vpn_import_handler(httpd_req_t *req)
{
    if (!check_csrf(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "CSRF rejected /api/vpn-import from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "CSRF check failed");
        return ESP_FAIL;
    }
    if (is_web_password_set() && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /api/vpn-import from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not authenticated");
        return ESP_FAIL;
    }

    if (req->content_len == 0 || req->content_len > 4096) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Invalid body size\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char *body = malloc(req->content_len + 1);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }

    int total = 0;
    while (total < req->content_len) {
        int ret = httpd_req_recv(req, body + total, req->content_len - total);
        if (ret <= 0) {
            free(body);
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) httpd_resp_send_408(req);
            return ESP_FAIL;
        }
        total += ret;
    }
    body[total] = '\0';

    esp_err_t err = vpn_import_conf(body);
    free(body);

    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        httpd_resp_send(req, "{\"ok\":true,\"msg\":\"WireGuard config imported. Rebooting...\"}", HTTPD_RESP_USE_STRLEN);
        esp_timer_start_once(restart_timer, 3000000);
    } else {
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Import failed: need PrivateKey, PublicKey, Endpoint and Address\"}", HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

static httpd_uri_t vpn_importp = {
    .uri       = "/api/vpn-import",
    .method    = HTTP_POST,
    .handler   = vpn_import_handler,
};

/* --- OTA Firmware Upload handler --- */

static esp_err_t ota_upload_handler(httpd_req_t *req)
{
    if (!check_csrf(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "CSRF rejected /api/ota-upload from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "CSRF check failed");
        return ESP_FAIL;
    }
    bool password_protection_enabled = is_web_password_set();
    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /api/ota-upload from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not authenticated");
        return ESP_FAIL;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"No OTA partition found\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    if (req->content_len == 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Empty request\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    if (req->content_len > update_partition->size) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Firmware too large for partition\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "OTA upload: %d bytes -> partition '%s' at 0x%lx",
             req->content_len, update_partition->label, (unsigned long)update_partition->address);

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"OTA begin failed\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char *buf = malloc(4096);
    if (buf == NULL) {
        esp_ota_abort(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }

    int remaining = req->content_len;
    bool header_checked = false;

    while (remaining > 0) {
        int recv_len = httpd_req_recv(req, buf, MIN(remaining, 4096));
        if (recv_len <= 0) {
            free(buf);
            esp_ota_abort(ota_handle);
            if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            return ESP_FAIL;
        }

        /* Validate firmware header on first chunk */
        if (!header_checked) {
            if (recv_len < (int)sizeof(esp_image_header_t)) {
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, "{\"ok\":false,\"msg\":\"File too small to be firmware\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            esp_image_header_t *hdr = (esp_image_header_t *)buf;
            if (hdr->magic != ESP_IMAGE_HEADER_MAGIC) {
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Invalid firmware file (bad magic)\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            if (hdr->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                    "{\"ok\":false,\"msg\":\"Wrong chip type (firmware: 0x%04X, this device: 0x%04X)\"}",
                    hdr->chip_id, CONFIG_IDF_FIRMWARE_CHIP_ID);
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            header_checked = true;
        }

        err = esp_ota_write(ota_handle, buf, recv_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"ok\":false,\"msg\":\"OTA write failed\"}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }

        remaining -= recv_len;
    }

    free(buf);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        char msg[128];
        snprintf(msg, sizeof(msg),
            "{\"ok\":false,\"msg\":\"Firmware validation failed: %s\"}",
            esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Failed to set boot partition\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "OTA update successful, rebooting in 3 seconds...");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true,\"msg\":\"Firmware updated! Rebooting...\"}", HTTPD_RESP_USE_STRLEN);

    esp_timer_start_once(restart_timer, 3000000);
    return ESP_OK;
}

static httpd_uri_t ota_uploadp = {
    .uri       = "/api/ota-upload",
    .method    = HTTP_POST,
    .handler   = ota_upload_handler,
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Page not found");
    return ESP_FAIL;
}

char* html_escape(const char* src) {
    //HTML escape for both attribute and element-content contexts.
    //Encodes < > & " ' \ # ; as numeric entities (&#NN;), so attacker-controlled
    //strings (e.g. scanned SSIDs) cannot inject markup or break out of attributes.
    int len = strlen(src);
    //Every char in the string + a null
    int esc_len = len + 1;

    for (int i = 0; i < len; i++) {
        if (src[i] == '\\' || src[i] == '\'' || src[i] == '\"' || src[i] == '&' || src[i] == '#' || src[i] == ';' || src[i] == '<' || src[i] == '>') {
            //Will be replaced with a 5 char sequence
            esc_len += 4;
        }
    }

    char* res = malloc(sizeof(char) * esc_len);
    if (res == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for HTML escaping");
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < len; i++) {
        if (src[i] == '\\' || src[i] == '\'' || src[i] == '\"' || src[i] == '&' || src[i] == '#' || src[i] == ';' || src[i] == '<' || src[i] == '>') {
            res[j++] = '&';
            res[j++] = '#';
            res[j++] = '0' + (src[i] / 10);
            res[j++] = '0' + (src[i] % 10);
            res[j++] = ';';
        }
        else {
            res[j++] = src[i];
        }
    }
    res[j] = '\0';

    return res;
}

/* --- Static assets -------------------------------------------------------
 *
 * app.css, app.js and favicon.svg live in components/http_server/www/ and are
 * gzipped into the image at build time (see CMakeLists.txt).  Serving them as
 * separate cacheable files is what lets the page templates drop their own
 * <style> blocks.
 *
 * The validator is the running app's ELF hash, so an OTA update invalidates
 * every asset at once.  Cache-Control is "no-cache" rather than a long max-age
 * on purpose: asset URLs are not versioned (wildcard URI matching is off), so a
 * cached stylesheet would otherwise outlive the markup it belongs to.  The cost
 * is one small conditional request per page load instead of re-sending the CSS.
 */

extern const uint8_t app_css_gz_start[]     asm("_binary_app_css_gz_start");
extern const uint8_t app_css_gz_end[]       asm("_binary_app_css_gz_end");
extern const uint8_t app_js_gz_start[]      asm("_binary_app_js_gz_start");
extern const uint8_t app_js_gz_end[]        asm("_binary_app_js_gz_end");
extern const uint8_t favicon_svg_gz_start[] asm("_binary_favicon_svg_gz_start");
extern const uint8_t favicon_svg_gz_end[]   asm("_binary_favicon_svg_gz_end");

static char s_asset_etag[20];

static const char *asset_etag(void)
{
    if (s_asset_etag[0] == '\0') {
        const esp_app_desc_t *desc = esp_app_get_description();
        snprintf(s_asset_etag, sizeof(s_asset_etag), "\"%02x%02x%02x%02x%02x%02x%02x%02x\"",
                 desc->app_elf_sha256[0], desc->app_elf_sha256[1],
                 desc->app_elf_sha256[2], desc->app_elf_sha256[3],
                 desc->app_elf_sha256[4], desc->app_elf_sha256[5],
                 desc->app_elf_sha256[6], desc->app_elf_sha256[7]);
    }
    return s_asset_etag;
}

static esp_err_t send_static_gz(httpd_req_t *req, const char *ctype,
                                const uint8_t *start, const uint8_t *end)
{
    const char *etag = asset_etag();
    char inm[24];

    if (httpd_req_get_hdr_value_str(req, "If-None-Match", inm, sizeof(inm)) == ESP_OK &&
        strcmp(inm, etag) == 0) {
        httpd_resp_set_status(req, "304 Not Modified");
        httpd_resp_set_hdr(req, "ETag", etag);
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    httpd_resp_set_type(req, ctype);
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "ETag", etag);
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, (const char *)start, end - start);
}

static esp_err_t app_css_handler(httpd_req_t *req) {
    return send_static_gz(req, "text/css", app_css_gz_start, app_css_gz_end);
}

static esp_err_t app_js_handler(httpd_req_t *req) {
    return send_static_gz(req, "application/javascript", app_js_gz_start, app_js_gz_end);
}

static esp_err_t favicon_get_handler(httpd_req_t *req) {
    return send_static_gz(req, "image/svg+xml", favicon_svg_gz_start, favicon_svg_gz_end);
}

static const httpd_uri_t app_css_uri = {
    .uri = "/app.css", .method = HTTP_GET, .handler = app_css_handler, .user_ctx = NULL
};

static const httpd_uri_t app_js_uri = {
    .uri = "/app.js", .method = HTTP_GET, .handler = app_js_handler, .user_ctx = NULL
};

static const httpd_uri_t favicon_uri = {
    .uri       = "/favicon.svg",
    .method    = HTTP_GET,
    .handler   = favicon_get_handler,
    .user_ctx  = NULL
};

/* Older bookmarks and any not-yet-migrated template still ask for this. */
static const httpd_uri_t favicon_png_uri = {
    .uri       = "/favicon.png",
    .method    = HTTP_GET,
    .handler   = favicon_get_handler,
    .user_ctx  = NULL
};

/* --- Shared page chrome --------------------------------------------------
 *
 * One nav bar on every page replaces the seven hand-written headers and the
 * "Home" button that used to sit at the bottom of each one.
 */

/* The tab id is stored rather than inferred from the index: the Ethernet build
 * drops two entries, which would otherwise shift every highlight. */
static const struct { const char *href; const char *label; page_tab_t tab; } NAV[] = {
    { "/",         "Status",   TAB_HOME     },
#if !CONFIG_ETH_UPLINK
    { "/setup",    "Setup",    TAB_SETUP    },
    { "/scan",     "Scan",     TAB_SCAN     },
#endif
    { "/config",   "Config",   TAB_CONFIG   },
    { "/mappings", "Mappings", TAB_MAPPINGS },
    { "/firewall", "Firewall", TAB_FIREWALL },
    { "/vpn",      "VPN",      TAB_VPN      },
};

/* Emits everything up to the start of the page body. 'active' highlights one
 * tab; pass TAB_NONE for pages that are not in the bar. Passing show_logout
 * false keeps the button off the pre-login page. */
static esp_err_t send_page_head(httpd_req_t *req, const char *title,
                                page_tab_t active, bool show_logout)
{
    SEND_CHUNK(req, DOC_HEAD_A, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, title, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, DOC_HEAD_B, HTTPD_RESP_USE_STRLEN);

    SEND_CHUNK(req, HDR_A, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, title, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, HDR_B, HTTPD_RESP_USE_STRLEN);
    if (show_logout) {
        SEND_CHUNK(req, LOGOUT_FORM, HTTPD_RESP_USE_STRLEN);
    }
    SEND_CHUNK(req, HDR_C, HTTPD_RESP_USE_STRLEN);

    SEND_CHUNK(req, NAV_OPEN, HTTPD_RESP_USE_STRLEN);
    for (size_t i = 0; i < sizeof(NAV) / sizeof(NAV[0]); i++) {
        char link[80];
        int n = snprintf(link, sizeof(link), "<a href=%s%s>%s</a>",
                         NAV[i].href,
                         NAV[i].tab == active ? " class=a" : "",
                         NAV[i].label);
        SEND_CHUNK(req, link, n);
    }
    SEND_CHUNK(req, NAV_CLOSE, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t send_page_foot(httpd_req_t *req)
{
    const esp_app_desc_t *d = esp_app_get_description();
    char buf[192];
    int n = snprintf(buf, sizeof(buf),
                     "v%s &middot; %s %s &middot; IDF " IDF_VER " &middot; "
                     "<a href=https://github.com/martin-ger/esp32_nat_router "
                     "target=_blank rel=noopener>Source</a>",
                     d->version, d->date, d->time);
    SEND_CHUNK(req, DOC_FOOT_A, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, buf, n);
    SEND_CHUNK(req, DOC_FOOT_B, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* Index page GET handler - System Status with navigation */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    char *form = NULL;
    char param[128];
    char param2[128];
    char login_message[256] = "";
    bool authenticated = false;
    bool password_protection_enabled = is_web_password_set();

    /* Signing in, signing out and changing the password all POST: it keeps the
     * password out of the URL, and a POST is the only kind of request that
     * carries an Origin header for check_csrf() to verify.  The one thing still
     * read from the query string is auth_required=, which picks a message. */
    if (!take_form(req, &form)) {
        return ESP_OK;
    }

    if (form != NULL) {
            /* Handle logout */
            if (httpd_query_key_value(form, "logout", param, sizeof(param)) == ESP_OK) {
                clear_session();
                strcpy(login_message, "Logged out successfully.");
            }

            /* Handle login */
            else if (httpd_query_key_value(form, "login_password", param, sizeof(param)) == ESP_OK) {
                preprocess_string(param);
                if (password_protection_enabled && verify_web_password(param)) {
                    create_session(req);
                    { char _ip[16]; ESP_LOGI(TAG, "Web UI login successful from %s", get_client_ip(req, _ip, sizeof(_ip))); }
                    free(form);
                    /* Redirect to reload page with session cookie */
                    httpd_resp_set_status(req, "303 See Other");
                    httpd_resp_set_hdr(req, "Location", "/");
                    httpd_resp_send(req, NULL, 0);
                    return ESP_OK;
                } else {
                    char ip[16];
                    ESP_LOGW(TAG, "Web UI login failed: incorrect password from %s", get_client_ip(req, ip, sizeof(ip)));
                    strcpy(login_message, "ERROR: Incorrect password.");
                }
            }

            /* Handle password change.  take_form() already ran the CSRF check
             * that used to sit here, and it now covers login and logout too. */
            else if (httpd_query_key_value(form, "new_password", param, sizeof(param)) == ESP_OK &&
                     httpd_query_key_value(form, "confirm_password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param);
                preprocess_string(param2);

                // Check if user is authenticated or no password is currently set
                if (is_authenticated(req) || !password_protection_enabled) {
                    if (strcmp(param, param2) == 0) {
                        esp_err_t err = set_web_password_hashed(param);
                        if (err == ESP_OK) {
                            clear_session();  // Force re-login with new password
                            free(form);
                            /* Redirect to reload page */
                            httpd_resp_set_status(req, "303 See Other");
                            httpd_resp_set_hdr(req, "Location", "/");
                            httpd_resp_send(req, NULL, 0);
                            return ESP_OK;
                        } else {
                            strcpy(login_message, "ERROR: Failed to save password.");
                        }
                    } else {
                        strcpy(login_message, "ERROR: Passwords do not match.");
                    }
                } else {
                    char ip2[16];
                    ESP_LOGW(TAG, "Unauthorized attempt to change web password from %s", get_client_ip(req, ip2, sizeof(ip2)));
                    strcpy(login_message, "ERROR: Not authorized to change password.");
                }
            }
    } else {
        char query[96];
        if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
            httpd_query_key_value(query, "auth_required", param, sizeof(param)) == ESP_OK) {
            strcpy(login_message, "Please log in to access that page.");
        }
    }
    free(form);

    /* Check current authentication status */
    authenticated = is_authenticated(req);

    /* Reusable buffer for building dynamic content */
    char row[512];

    /* --- Begin chunked response --- */
    send_page_head(req, INDEX_TITLE, TAB_HOME, authenticated);

    SEND_CHUNK(req, INDEX_CHUNK_STATUS_OPEN, HTTPD_RESP_USE_STRLEN);

    /* Stream AP status rows */
    if (ap_disabled) {
        SEND_CHUNK(req,
            "<tr><td>AP interface</td><td><span class=\"bd er\">Disabled</span></td></tr>",
            HTTPD_RESP_USE_STRLEN);
    } else {
        char* safe_ap_ssid = html_escape(ap_ssid);
        if (safe_ap_ssid == NULL) safe_ap_ssid = strdup("(unknown)");
        snprintf(row, sizeof(row), "<tr><td>SSID</td><td><strong>%s</strong></td></tr>",
                 safe_ap_ssid ? safe_ap_ssid : "");
        /* Free before SEND_CHUNK: a bail-out on a dead client returns immediately. */
        free(safe_ap_ssid);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

        esp_ip4_addr_t ap_addr;
        ap_addr.addr = my_ap_ip;
        snprintf(row, sizeof(row), "<tr><td>AP address</td><td>" IPSTR "</td></tr>", IP2STR(&ap_addr));
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

        resync_connect_count();
        snprintf(row, sizeof(row), "<tr><td>Clients</td><td>%d</td></tr>", connect_count);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Stream Uplink row */
#if CONFIG_ETH_UPLINK
    SEND_CHUNK(req, ap_connect
        ? "<tr><td>Uplink</td><td><span class=\"bd ok\">Ethernet connected</span></td></tr>"
        : "<tr><td>Uplink</td><td><span class=\"bd er\">Ethernet disconnected</span></td></tr>",
        HTTPD_RESP_USE_STRLEN);
#else
    if (ap_connect) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            snprintf(row, sizeof(row),
                     "<tr><td>Uplink</td><td><span class=\"bd ok\">Connected</span> "
                     "<span class=n>%d dBm</span></td></tr>", ap_info.rssi);
            SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
        } else {
            SEND_CHUNK(req, "<tr><td>Uplink</td><td><span class=\"bd ok\">Connected</span></td></tr>",
                       HTTPD_RESP_USE_STRLEN);
        }
    } else {
        SEND_CHUNK(req, "<tr><td>Uplink</td><td><span class=\"bd er\">Disconnected</span></td></tr>",
                   HTTPD_RESP_USE_STRLEN);
    }
#endif

    /* Stream uplink IP row */
#if CONFIG_ETH_UPLINK
    const char *uplink_label = "Ethernet address";
#else
    const char *uplink_label = "Uplink address";
#endif
    if (ap_connect) {
        esp_ip4_addr_t addr;
        addr.addr = my_ip;
        snprintf(row, sizeof(row), "<tr><td>%s</td><td>" IPSTR "</td></tr>",
                 uplink_label, IP2STR(&addr));
    } else {
        snprintf(row, sizeof(row), "<tr><td>%s</td><td class=n>not assigned</td></tr>", uplink_label);
    }
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream VPN status row */
    if (vpn_enabled) {
        const char *vpn_cls, *vpn_txt;
        if (vpn_is_connected())   { vpn_cls = "ok"; vpn_txt = "Connected"; }
        else if (vpn_connected)   { vpn_cls = "wn"; vpn_txt = "Handshake pending"; }
        else                      { vpn_cls = "er"; vpn_txt = "Disconnected"; }
        snprintf(row, sizeof(row), "<tr><td>VPN</td><td><span class=\"bd %s\">%s</span></td></tr>",
                 vpn_cls, vpn_txt);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Stream Bytes row (sent/received combined) */
    uint64_t bytes_sent = get_sta_bytes_sent();
    uint64_t bytes_received = get_sta_bytes_received();
    char sent_buf[16], recv_buf[16];
    format_bytes_human(bytes_sent, sent_buf, sizeof(sent_buf));
    format_bytes_human(bytes_received, recv_buf, sizeof(recv_buf));
    snprintf(row, sizeof(row), "<tr><td>Traffic</td><td>%s sent, %s received</td></tr>",
             sent_buf, recv_buf);
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Monitoring row */
    pcap_capture_mode_t mode = pcap_get_mode();
    if (mode != PCAP_MODE_OFF) {
        snprintf(row, sizeof(row),
                 "<tr><td>Monitoring</td><td><span class=\"bd ok\">%s</span> "
                 "<span class=n>%lu captured, %lu dropped</span></td></tr>",
                 (mode == PCAP_MODE_ACL_MONITOR) ? "ACL monitor" : "Promiscuous",
                 (unsigned long)pcap_get_captured_count(),
                 (unsigned long)pcap_get_dropped_count());
    } else {
        snprintf(row, sizeof(row), "<tr><td>Monitoring</td><td class=n>Off</td></tr>");
    }
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Uptime row */
    char uptime_str[32];
    format_uptime(get_uptime_seconds(), uptime_str, sizeof(uptime_str));
    char boot_time_str[32];
    format_boot_time(boot_time_str, sizeof(boot_time_str));
    snprintf(row, sizeof(row), "<tr><td>Uptime</td><td>%s <span class=n>since %s</span></td></tr>",
             uptime_str, boot_time_str);
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    SEND_CHUNK(req, INDEX_CHUNK_STATUS_CLOSE, HTTPD_RESP_USE_STRLEN);

    /* --- Auth UI --- */

    if (login_message[0] != '\0') {
        /* login_message is built from fixed strings only, never from request
         * data, so it needs no escaping here. */
        snprintf(row, sizeof(row), "<p class=\"al %s\">%s</p>",
                 strstr(login_message, "ERROR") ? "er" : "ok", login_message);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    if (!password_protection_enabled) {
        SEND_CHUNK(req,
            "<p class=\"al wn\"><strong>No password set.</strong> "
            "Anyone on this network can change the router's settings.</p>",
            HTTPD_RESP_USE_STRLEN);
    }

    if (password_protection_enabled && !authenticated) {
        SEND_CHUNK(req,
            "<div class=c><h2>Sign in</h2>"
            "<form action=/ method=POST class=f>"
            /* Hidden username field gives iOS/Safari and password managers an account
             * to associate the saved password with, so AutoFill works on this
             * password-only login instead of demanding a username. */
            "<input type=text name=username value=admin autocomplete=username "
            "style=display:none aria-hidden=true tabindex=-1>"
            "<label for=pw>Password</label>"
            "<input id=pw type=password name=login_password autocomplete=current-password>"
            "<button class=\"b p act\" type=submit>Sign in</button>"
            "</form></div>", HTTPD_RESP_USE_STRLEN);
    }

    if (authenticated || !password_protection_enabled) {
        const char* form_title = password_protection_enabled ? "Change password" : "Set a password";
        SEND_CHUNK(req, "<div class=c><h2>", HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, form_title, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req,
            "</h2>"
            /* POST keeps the new password out of the URL and makes the Origin-header
             * CSRF check effective (browsers send Origin on POST but not GET). */
            "<form action=/ method=POST class=f>"
            "<label for=np>New password</label>"
            "<input id=np type=password name=new_password autocomplete=new-password>"
            "<label for=cp>Repeat</label>"
            "<input id=cp type=password name=confirm_password autocomplete=new-password>"
            "<p class=hint>Leave both empty to turn password protection off.</p>"
            "<button class=\"b p act\" type=submit>", HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, form_title, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, "</button></form></div>", HTTPD_RESP_USE_STRLEN);
    }

    send_page_foot(req);

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t indexp = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
};

/* Same handler also serves POST so the login form can submit its password in the
 * request body instead of the URL query string. */
static httpd_uri_t indexp_post = {
    .uri       = "/",
    .method    = HTTP_POST,
    .handler   = index_get_handler,
};

uint8_t web_ui_get_bind(void)
{
    return s_web_bind;
}

void web_ui_set_bind(uint8_t bind)
{
    if (bind == 0) bind = RC_BIND_AP;  /* must keep at least one */
    s_web_bind = bind & (RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN);
    set_config_param_int("web_bind", (int32_t)s_web_bind);
    char buf[20] = "";
    if (s_web_bind & RC_BIND_AP)  strcat(buf, "AP ");
#if CONFIG_ETH_UPLINK
    if (s_web_bind & RC_BIND_STA) strcat(buf, "ETH ");
#else
    if (s_web_bind & RC_BIND_STA) strcat(buf, "STA ");
#endif
    if (s_web_bind & RC_BIND_VPN) strcat(buf, "VPN ");
    ESP_LOGI(TAG, "Web UI bind set to: %s", buf);
}

/* Router Config page GET handler */
static esp_err_t config_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    /* Check authentication if password protection is enabled */
    bool password_protection_enabled = is_web_password_set();

    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /config from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char *form;
    if (!take_form(req, &form)) {
        return ESP_OK;
    }
    /* Set by every branch below that queues a restart, so the rendered page can
     * say so.  This used to be a script that matched the query string against a
     * list of field names and replaced document.body when one hit — which meant
     * the page claimed a reboot for any URL carrying, say, ?reset= . */
    bool restarting = false;

    if (form != NULL) {
        char reset_param[16];
        if (httpd_query_key_value(form, "reset", reset_param, sizeof(reset_param)) == ESP_OK) {
            esp_timer_start_once(restart_timer, 500000);
            restarting = true;
        }

        /* Handle Web UI bind interface settings */
        char param1[64];
        if (httpd_query_key_value(form, "web_bind_save", param1, sizeof(param1)) == ESP_OK) {
            uint8_t bind = 0;
            if (httpd_query_key_value(form, "web_bind_ap",  param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_AP;
            if (httpd_query_key_value(form, "web_bind_sta", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_STA;
            if (httpd_query_key_value(form, "web_bind_vpn", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_VPN;
            if (bind == 0) bind = RC_BIND_AP;
            web_ui_set_bind(bind);
            ESP_LOGI(TAG, "Web UI bind interfaces updated via web");
            free(form);
            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/config");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        }

        /* Handle disable interface button */
        if (strstr(form, "disable_interface=") != NULL) {
            ESP_LOGI(TAG, "Disabling web interface");
            if (set_config_param_str("web_disabled", "1") == ESP_OK) {
                ESP_LOGI(TAG, "Web interface disabled. Use 'enable' command via serial to re-enable.");
            }
            esp_timer_start_once(restart_timer, 500000);
            restarting = true;
        }

        char param2[64];
        char param3[64];
        char param4[64];
        char param5[64];

        /* Handle AP settings with optional MAC and IP */
        if (httpd_query_key_value(form, "ap_ssid", param1, sizeof(param1)) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query parameter => ap_ssid=%s", param1);
            preprocess_string(param1);
            if (httpd_query_key_value(form, "ap_password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param2);

                // "Open network" checkbox overrides password to empty
                {
                    char open_val[4] = "";
                    if (httpd_query_key_value(form, "ap_open", open_val, sizeof(open_val)) == ESP_OK) {
                        param2[0] = '\0';
                    } else if (strlen(param2) == 0) {
                        // Keep existing password if field was left empty
                        strlcpy(param2, ap_passwd, sizeof(param2));
                    }
                }

                // Set SSID and password
                int argc = 3;
                char* argv[3];
                argv[0] = "set_ap";
                argv[1] = param1;
                argv[2] = param2;
                set_ap(argc, argv);

                // Check for optional AP IP address
                if (httpd_query_key_value(form, "ap_ip_addr", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                    ESP_LOGI(TAG, "Found URL query parameter => ap_ip_addr=%s", param3);
                    preprocess_string(param3);
                    char* ip_argv[2];
                    ip_argv[0] = "set_ap_ip";
                    ip_argv[1] = param3;
                    set_ap_ip(2, ip_argv);
                }

                // Check for optional hostname (mDNS / DHCP name).
                // set_hostname validates (RFC 952) and updates the global.
                if (httpd_query_key_value(form, "ap_hostname", param4, sizeof(param4)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => ap_hostname=%s", param4);
                    char* host_argv[2];
                    host_argv[0] = "set_hostname";
                    host_argv[1] = param4;
                    set_hostname(2, host_argv);
                }

                // Check for optional AP DNS server
                {
                    char dns_param[64];
                    if (httpd_query_key_value(form, "ap_dns", dns_param, sizeof(dns_param)) == ESP_OK) {
                        preprocess_string(dns_param);
                        ESP_LOGI(TAG, "Found URL query parameter => ap_dns=%s", dns_param);
                        set_config_param_str("ap_dns", dns_param);
                        free(ap_dns);
                        ap_dns = strdup(dns_param);
                    }
                }

                // Check for optional AP MAC address
                if (httpd_query_key_value(form, "ap_mac", param4, sizeof(param4)) == ESP_OK && strlen(param4) > 0) {
                    ESP_LOGI(TAG, "Found URL query parameter => ap_mac=%s", param4);
                    preprocess_string(param4);
                    // Parse MAC address string (format: AA:BB:CC:DD:EE:FF)
                    unsigned int mac[6];
                    if (sscanf(param4, "%02x:%02x:%02x:%02x:%02x:%02x",
                               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        char mac_str[6][4];
                        for (int i = 0; i < 6; i++) {
                            sprintf(mac_str[i], "%d", mac[i]);
                        }
                        char* mac_argv[7];
                        mac_argv[0] = "set_ap_mac";
                        for (int i = 0; i < 6; i++) {
                            mac_argv[i+1] = mac_str[i];
                        }
                        set_ap_mac(7, mac_argv);
                    }
                }

                // Handle AP enabled/disabled setting
                // Checkbox sends value only when checked, so absence means "disabled"
                {
                    bool ap_en = (httpd_query_key_value(form, "ap_enabled", param5, sizeof(param5)) == ESP_OK);
                    set_config_param_int("ap_disabled", ap_en ? 0 : 1);
                    ap_disabled = !ap_en;
                    ESP_LOGI(TAG, "AP interface %s", ap_en ? "enabled" : "disabled");
                }

                // Handle AP NAT setting (checkbox: present = on, absent = off)
                {
                    int nat_val = (httpd_query_key_value(form, "ap_nat", param5, sizeof(param5)) == ESP_OK) ? 1 : 0;
                    set_config_param_int("ap_nat", nat_val);
                    ap_nat_enabled = (uint8_t)nat_val;
                    ESP_LOGI(TAG, "AP NAT %s", nat_val ? "enabled" : "disabled");
                }

                // Handle AP hidden SSID setting
                // Checkbox sends value only when checked, so absence means "off"
                {
                    int hidden_val = 0;
                    if (httpd_query_key_value(form, "ap_hidden", param5, sizeof(param5)) == ESP_OK) {
                        hidden_val = 1;
                        ESP_LOGI(TAG, "Found URL query parameter => ap_hidden=%s", param5);
                    }
                    set_config_param_int("ap_hidden", hidden_val);
                    ap_ssid_hidden = (uint8_t)hidden_val;
                    ESP_LOGI(TAG, "AP hidden SSID set to: %d", hidden_val);
                }

                // Handle AP auth mode setting
                if (httpd_query_key_value(form, "ap_auth", param5, sizeof(param5)) == ESP_OK) {
                    int auth_val = atoi(param5);
                    if (auth_val >= 0 && auth_val <= 2) {
                        set_config_param_int("ap_authmode", auth_val);
                        ap_authmode = (uint8_t)auth_val;
                        ESP_LOGI(TAG, "AP auth mode set to: %d", auth_val);
                    }
                }

#if CONFIG_ETH_UPLINK
                // Handle AP channel setting (ETH_UPLINK only)
                if (httpd_query_key_value(form, "ap_channel", param5, sizeof(param5)) == ESP_OK) {
                    int channel_val = atoi(param5);
                    if (channel_val >= 0 && channel_val <= 13) {
                        set_config_param_int("ap_channel", channel_val);
                        ap_channel = (uint8_t)channel_val;
                        ESP_LOGI(TAG, "AP channel set to: %d", channel_val);
                    }
                }
#endif

                esp_timer_start_once(restart_timer, 500000);
                restarting = true;
            }
        }

#if !CONFIG_ETH_UPLINK
        /* Handle STA settings with optional MAC */
        if (httpd_query_key_value(form, "ssid", param1, sizeof(param1)) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query parameter => ssid=%s", param1);
            preprocess_string(param1);
            if (httpd_query_key_value(form, "password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param2);

                // Keep existing password if field was left empty
                if (strlen(param2) == 0) {
                    strlcpy(param2, passwd, sizeof(param2));
                }
                if (httpd_query_key_value(form, "ent_username", param3, sizeof(param3)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => ent_username=%s", param3);
                    preprocess_string(param3);
                    if (httpd_query_key_value(form, "ent_identity", param4, sizeof(param4)) == ESP_OK) {
                        ESP_LOGI(TAG, "Found URL query parameter => ent_identity=%s", param4);
                        preprocess_string(param4);

                        int argc = 0;
                        char* argv[7];
                        argv[argc++] = "set_sta";
                        //SSID
                        argv[argc++] = param1;
                        //Password
                        argv[argc++] = param2;
                        //Username
                        if(strlen(param3)) {
                            argv[argc++] = "-u";
                            argv[argc++] = param3;
                        }
                        //Identity
                        if(strlen(param4)) {
                            argv[argc++] = "-a";
                            argv[argc++] = param4;
                        }

                        set_sta(argc, argv);

                        // Save WPA2-Enterprise settings to NVS
                        {
                            char phase2_param[4] = "";
                            int phase2_val = 0;
                            if (httpd_query_key_value(form, "ttls_phase2", phase2_param, sizeof(phase2_param)) == ESP_OK) {
                                phase2_val = atoi(phase2_param);
                            }
                            set_config_param_int("ttls_phase2", phase2_val);
                            ttls_phase2 = phase2_val;

                            // Checkboxes: present = 1, absent = 0
                            char cb_param[4] = "";
                            int cb_val = 0;
                            if (httpd_query_key_value(form, "cert_bundle", cb_param, sizeof(cb_param)) == ESP_OK) {
                                cb_val = 1;
                            }
                            set_config_param_int("cert_bundle", cb_val);
                            use_cert_bundle = cb_val;

                            int tc_val = 0;
                            if (httpd_query_key_value(form, "no_time_chk", cb_param, sizeof(cb_param)) == ESP_OK) {
                                tc_val = 1;
                            }
                            set_config_param_int("no_time_chk", tc_val);
                            disable_time_check = tc_val;
                        }

#if WIFI_HAS_5GHZ
                        // Save STA band preference
                        {
                            char band_param[4] = "";
                            int band_val = STA_BAND_AUTO;
                            if (httpd_query_key_value(form, "sta_band", band_param, sizeof(band_param)) == ESP_OK) {
                                band_val = atoi(band_param);
                                if (band_val < STA_BAND_AUTO || band_val > STA_BAND_5G)
                                    band_val = STA_BAND_AUTO;
                            }
                            set_config_param_int("sta_band", band_val);
                            sta_band = (uint8_t)band_val;
                        }
#endif

                        // Check for optional STA MAC address
                        if (httpd_query_key_value(form, "sta_mac", param5, sizeof(param5)) == ESP_OK && strlen(param5) > 0) {
                            ESP_LOGI(TAG, "Found URL query parameter => sta_mac=%s", param5);
                            preprocess_string(param5);
                            // Parse MAC address string (format: AA:BB:CC:DD:EE:FF)
                            unsigned int mac[6];
                            if (sscanf(param5, "%02x:%02x:%02x:%02x:%02x:%02x",
                                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                                char mac_str[6][4];
                                for (int i = 0; i < 6; i++) {
                                    sprintf(mac_str[i], "%d", mac[i]);
                                }
                                char* mac_argv[7];
                                mac_argv[0] = "set_sta_mac";
                                for (int i = 0; i < 6; i++) {
                                    mac_argv[i+1] = mac_str[i];
                                }
                                set_sta_mac(7, mac_argv);
                            }
                        }

                        esp_timer_start_once(restart_timer, 500000);
                        restarting = true;
                    }
                }
            }
        }
#endif

        /* Handle static IP settings */
        if (httpd_query_key_value(form, "staticip", param1, sizeof(param1)) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query parameter => staticip=%s", param1);
            preprocess_string(param1);
            if (httpd_query_key_value(form, "subnetmask", param2, sizeof(param2)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => subnetmask=%s", param2);
                preprocess_string(param2);
                if (httpd_query_key_value(form, "gateway", param3, sizeof(param3)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => gateway=%s", param3);
                    preprocess_string(param3);
                    int argc = 4;
                    char* argv[4];
                    argv[0] = "set_sta_static";
                    argv[1] = param1;
                    argv[2] = param2;
                    argv[3] = param3;
                    set_sta_static(argc, argv);
                    esp_timer_start_once(restart_timer, 500000);
                    restarting = true;
                }
            }
        }

        /* Handle Remote Console kick.
         * Tested before the settings save below: the Disconnect button
         * lives inside the settings form, so a click on it carries
         * rc_save=1 as well and the save would answer first. */
        if (httpd_query_key_value(form, "rc_kick", param1, sizeof(param1)) == ESP_OK) {
            remote_console_kick();
            ESP_LOGI(TAG, "Remote console session kicked via web");
            free(form);
            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/config");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        }

        /* Handle Remote Console settings (single form) */
        if (httpd_query_key_value(form, "rc_save", param1, sizeof(param1)) == ESP_OK) {
            /* Enable/disable */
            if (httpd_query_key_value(form, "rc_enabled", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                if (strcmp(param1, "1") == 0) {
                    remote_console_enable();
                } else {
                    remote_console_disable();
                }
            }
            /* Port */
            if (httpd_query_key_value(form, "rc_port", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int port = atoi(param1);
                if (port >= 1 && port <= 65535) {
                    remote_console_set_port((uint16_t)port);
                }
            }
            /* Bind interfaces (checkboxes: absent = unchecked) */
            uint8_t bind = 0;
            if (httpd_query_key_value(form, "rc_bind_ap", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_AP;
            if (httpd_query_key_value(form, "rc_bind_sta", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_STA;
            if (httpd_query_key_value(form, "rc_bind_vpn", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_VPN;
            if (bind == 0) bind = RC_BIND_AP;
            remote_console_set_bind(bind);
            /* Timeout */
            if (httpd_query_key_value(form, "rc_timeout", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int timeout = atoi(param1);
                if (timeout >= 0) {
                    remote_console_set_timeout((uint32_t)timeout);
                }
            }
            ESP_LOGI(TAG, "Remote console settings saved via web");
            free(form);
            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/config");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        }

        /* Handle PCAP settings (single form) */
        if (httpd_query_key_value(form, "pcap_save", param1, sizeof(param1)) == ESP_OK) {
            if (httpd_query_key_value(form, "pcap_mode", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                if (strcmp(param1, "off") == 0) {
                    pcap_set_mode(PCAP_MODE_OFF);
                } else if (strcmp(param1, "acl") == 0) {
                    pcap_set_mode(PCAP_MODE_ACL_MONITOR);
                } else if (strcmp(param1, "promisc") == 0) {
                    pcap_set_mode(PCAP_MODE_PROMISCUOUS);
                }
            }
            if (httpd_query_key_value(form, "pcap_snaplen", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int snaplen = atoi(param1);
                if (snaplen >= 64 && snaplen <= 1600) {
                    pcap_set_snaplen((uint16_t)snaplen);
                }
            }
            ESP_LOGI(TAG, "PCAP settings saved via web");
            free(form);
            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/config");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        }
        free(form);
    }

#if !CONFIG_ETH_UPLINK
    /* Check for SSID pre-fill from the scan page.  A read, so it stays on the
     * query string: /config?ssid=... only fills a field in. */
    char prefill_ssid[64] = "";
    size_t query_len = httpd_req_get_url_query_len(req) + 1;
    if (query_len > 1) {
        char *query = malloc(query_len);
        if (query != NULL) {
            if (httpd_req_get_url_query_str(req, query, query_len) == ESP_OK &&
                httpd_query_key_value(query, "ssid", prefill_ssid, sizeof(prefill_ssid)) == ESP_OK) {
                preprocess_string(prefill_ssid);
            }
            free(query);
        }
    }

    /* Escape values into stack buffers and release the heap copies immediately.
     * Holding html_escape() allocations across the chunked render below would
     * leak them whenever a SEND_CHUNK bails out on a dead client. */
    char safe_ssid[200], safe_ent_username[256], safe_ent_identity[256];
    html_escape_to(safe_ssid, sizeof(safe_ssid), prefill_ssid[0] ? prefill_ssid : ssid);
    html_escape_to(safe_ent_username, sizeof(safe_ent_username), ent_username);
    html_escape_to(safe_ent_identity, sizeof(safe_ent_identity), ent_identity);
#endif
    char safe_ap_ssid[200];
    html_escape_to(safe_ap_ssid, sizeof(safe_ap_ssid), ap_ssid);

    /* Addresses and the hostname are escaped too.  They look like they could
     * not hold markup, but nothing on the way in guarantees that: a restored
     * configuration file or a console command can put any bytes in these NVS
     * strings, and they land inside value='...' below. */
    char safe_hostname[200], safe_ap_dns[96];
    html_escape_to(safe_hostname, sizeof(safe_hostname), hostname);
    html_escape_to(safe_ap_dns, sizeof(safe_ap_dns), ap_dns);

    char safe_static_ip[96], safe_subnet_mask[96], safe_gateway[96];
    html_escape_to(safe_static_ip, sizeof(safe_static_ip), static_ip);
    html_escape_to(safe_subnet_mask, sizeof(safe_subnet_mask), subnet_mask);
    html_escape_to(safe_gateway, sizeof(safe_gateway), gateway_addr);

    // Get current AP IP address.  Copy into a stack buffer and free the heap
    // copy now, for the same reason as the escaped strings above.
    char safe_ap_ip[96];
    {
        char ap_ip_str[64] = "";
        char *ap_ip_param = NULL;
        get_config_param_str("ap_ip", &ap_ip_param);
        if (ap_ip_param != NULL) {
            strlcpy(ap_ip_str, ap_ip_param, sizeof(ap_ip_str));
            free(ap_ip_param);
        } else {
            snprintf(ap_ip_str, sizeof(ap_ip_str), IPSTR, IP2STR((esp_ip4_addr_t *)&my_ap_ip));
        }
        html_escape_to(safe_ap_ip, sizeof(safe_ap_ip), ap_ip_str);
    }

    // Get MAC addresses as strings
    char ap_mac_str[18] = "";
    uint8_t mac[6];
    if (esp_wifi_get_mac(ESP_IF_WIFI_AP, mac) == ESP_OK) {
        sprintf(ap_mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
#if !CONFIG_ETH_UPLINK
    char sta_mac_str[18] = "";
    if (esp_wifi_get_mac(ESP_IF_WIFI_STA, mac) == ESP_OK) {
        sprintf(sta_mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
#endif

    // Remote Console state
    remote_console_config_t rc_config;
    remote_console_status_t rc_status;
    remote_console_get_config(&rc_config);
    remote_console_get_status(&rc_status);

    /* Reusable buffer for building sections.  Stack, not heap: a SEND_CHUNK
     * bail-out on a dead client returns immediately.  Sized for the largest
     * section (the access point form) once its escaped SSID and hostname are
     * accounted for as fixed-size stack buffers. */
    char section[2560];
    int n;

    httpd_resp_set_type(req, "text/html");

    if (send_page_head(req, "Configuration", TAB_CONFIG,
                       session_active && password_protection_enabled) != ESP_OK) {
        return ESP_FAIL;
    }

    if (restarting) {
        SEND_CHUNK(req, CONFIG_REBOOT_NOTE, HTTPD_RESP_USE_STRLEN);
    }

    SEND_CHUNK(req, CONFIG_OPEN, HTTPD_RESP_USE_STRLEN);

    /* Access point --------------------------------------------------------- */

    n = snprintf(section, sizeof(section), CONFIG_AP,
        safe_ap_ssid, safe_ap_ip, safe_hostname, safe_ap_dns, ap_mac_str,
#if CONFIG_ETH_UPLINK
        (int)ap_channel,
#endif
        ap_authmode == 0 ? "selected" : "",
        ap_authmode == 1 ? "selected" : "",
        ap_authmode == 2 ? "selected" : "",
        ap_nat_enabled ? "checked" : "",
        ap_disabled ? "" : "checked",
        (strlen(ap_passwd) == 0) ? "checked" : "",
        ap_ssid_hidden ? "checked" : "");
    SEND_RENDERED(req, section, n);

    /* Uplink --------------------------------------------------------------- */

#if CONFIG_ETH_UPLINK
    SEND_CHUNK(req, CONFIG_STA, HTTPD_RESP_USE_STRLEN);
#else
    n = snprintf(section, sizeof(section), CONFIG_STA,
        safe_ssid,
#if WIFI_HAS_5GHZ
        sta_band == STA_BAND_AUTO ? "selected" : "",
        sta_band == STA_BAND_2G ? "selected" : "",
        sta_band == STA_BAND_5G ? "selected" : "",
#endif
        sta_mac_str,
        safe_ent_username, safe_ent_identity,
        ttls_phase2 == 0 ? "selected" : "", ttls_phase2 == 1 ? "selected" : "",
        ttls_phase2 == 2 ? "selected" : "", ttls_phase2 == 3 ? "selected" : "",
        use_cert_bundle ? "checked" : "", disable_time_check ? "checked" : "");
    SEND_RENDERED(req, section, n);
#endif

    n = snprintf(section, sizeof(section), CONFIG_STATIC,
                 safe_static_ip, safe_subnet_mask, safe_gateway);
    SEND_RENDERED(req, section, n);

    /* Remote console ------------------------------------------------------- */

    {
        const char *rc_class, *rc_text;
        /* Only an established session can be kicked, so the button exists only
         * in that state; the format string takes an empty string otherwise. */
        const char *rc_kick = "";
        switch (rc_status.state) {
            case RC_STATE_LISTENING:
                rc_class = "bd ok"; rc_text = "Listening";
                break;
            case RC_STATE_AUTH_WAIT:
                rc_class = "bd wn"; rc_text = "Authenticating";
                break;
            case RC_STATE_ACTIVE:
                rc_class = "bd ok"; rc_text = rc_status.client_ip;
                /* A plain button in the surrounding settings form, not a
                 * form of its own: a nested <form> is dropped by the parser
                 * and its button silently submits the outer one instead. */
                rc_kick = " <button class=\"b s d\" name=rc_kick value=1 "
                          "data-c='Disconnect the console session?'>Disconnect"
                          "</button>";
                break;
            case RC_STATE_DISABLED:
                rc_class = "n"; rc_text = "Disabled";
                break;
            default:
                rc_class = "n"; rc_text = "Unknown";
                break;
        }
        n = snprintf(section, sizeof(section), CONFIG_RC,
            rc_config.enabled ? "selected" : "",
            rc_config.enabled ? "" : "selected",
            rc_class, rc_text, rc_kick,
            rc_config.port,
            (rc_config.bind & RC_BIND_AP)  ? "checked" : "",
            (rc_config.bind & RC_BIND_STA) ? "checked" : "",
            (rc_config.bind & RC_BIND_VPN) ? "checked" : "",
            (unsigned long)rc_config.idle_timeout_sec);
        SEND_RENDERED(req, section, n);
    }

    /* Packet capture ------------------------------------------------------- */

    {
        pcap_capture_mode_t pcap_mode = pcap_get_mode();
        bool pcap_client = pcap_client_connected();
        char sta_ip_str[16];
        ip4_addr_t sta_addr;
        sta_addr.addr = my_ip;
        snprintf(sta_ip_str, sizeof(sta_ip_str), IPSTR, IP2STR(&sta_addr));

        n = snprintf(section, sizeof(section), CONFIG_PCAP,
            pcap_mode == PCAP_MODE_OFF ? "selected" : "",
            pcap_mode == PCAP_MODE_ACL_MONITOR ? "selected" : "",
            pcap_mode == PCAP_MODE_PROMISCUOUS ? "selected" : "",
            pcap_client ? "bd ok" : "n",
            pcap_client ? "Connected" : "Not connected",
            (unsigned long)pcap_get_captured_count(),
            (unsigned long)pcap_get_dropped_count(),
            (int)pcap_get_snaplen(), sta_ip_str);
        SEND_RENDERED(req, section, n);
    }

    /* Firmware ------------------------------------------------------------- */

    {
        esp_chip_info_t chip_info;
        esp_chip_info(&chip_info);
        const char *chip_model;
        switch (chip_info.model) {
            case CHIP_ESP32:   chip_model = "ESP32"; break;
            case CHIP_ESP32S2: chip_model = "ESP32-S2"; break;
            case CHIP_ESP32S3: chip_model = "ESP32-S3"; break;
            case CHIP_ESP32C3: chip_model = "ESP32-C3"; break;
            case CHIP_ESP32C2: chip_model = "ESP32-C2"; break;
            case CHIP_ESP32C5: chip_model = "ESP32-C5"; break;
            case CHIP_ESP32C6: chip_model = "ESP32-C6"; break;
            case CHIP_ESP32H2: chip_model = "ESP32-H2"; break;
            default:           chip_model = "Unknown"; break;
        }
        const esp_partition_t *running = esp_ota_get_running_partition();
        const esp_app_desc_t *app_desc = esp_app_get_description();
        n = snprintf(section, sizeof(section), CONFIG_FIRMWARE,
            running ? running->label : "unknown",
            chip_model,
            app_desc ? app_desc->version : "unknown",
            app_desc ? app_desc->date : "", app_desc ? app_desc->time : "");
        SEND_RENDERED(req, section, n);
    }

    SEND_CHUNK(req, CONFIG_BACKUP, HTTPD_RESP_USE_STRLEN);

    /* Reboot and access ---------------------------------------------------- */

    n = snprintf(section, sizeof(section), CONFIG_DANGER,
        (s_web_bind & RC_BIND_AP)  ? "checked" : "",
        (s_web_bind & RC_BIND_STA) ? "checked" : "",
        (s_web_bind & RC_BIND_VPN) ? "checked" : "");
    SEND_RENDERED(req, section, n);

    SEND_CHUNK(req, CONFIG_CLOSE, HTTPD_RESP_USE_STRLEN);

    if (send_page_foot(req) != ESP_OK) {
        return ESP_FAIL;
    }

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    /* No cleanup needed: all escaped values live in stack buffers (the heap
     * copies were freed before streaming began). */
    return ESP_OK;
}

static httpd_uri_t configp = {
    .uri       = "/config",
    .method    = HTTP_GET,
    .handler   = config_get_handler,
};

/* Same function for both verbs: GET renders the page, POST applies the form
 * and then renders it. */
static httpd_uri_t configp_post = {
    .uri       = "/config",
    .method    = HTTP_POST,
    .handler   = config_get_handler,
};

/* Mappings page GET handler (DHCP Reservations + Port Forwarding) - Chunked transfer */
static esp_err_t mappings_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    /* Check authentication if password protection is enabled */
    bool password_protection_enabled = is_web_password_set();

    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /mappings from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char *form;
    if (!take_form(req, &form)) {
        return ESP_OK;
    }
    char error_msg[128] = "";

    /* The error message rides the query string of the redirect that a rejected
     * entry sends; everything that changes state comes out of the POST body. */
    read_error_param(req, error_msg, sizeof(error_msg));

    if (form != NULL) {
        char param1[64];
        char param2[64];
        char param3[64];
        char param4[64];

        /* Check for add DHCP reservation */
        if (httpd_query_key_value(form, "dhcp_action", param1, sizeof(param1)) == ESP_OK) {
            bool is_block = (strcmp(param1, "Block") == 0);
            if (strcmp(param1, "Add+Reservation") == 0 || strcmp(param1, "Add Reservation") == 0 || is_block) {
                if (httpd_query_key_value(form, "dhcp_mac", param1, sizeof(param1)) == ESP_OK &&
                    httpd_query_key_value(form, "dhcp_ip", param2, sizeof(param2)) == ESP_OK) {

                    preprocess_string(param1);
                    preprocess_string(param2);

                    const char *err_msg = NULL;

                    // Parse MAC address
                    unsigned int mac[6];
                    uint8_t mac_bytes[6];
                    if (sscanf(param1, "%02x:%02x:%02x:%02x:%02x:%02x",
                               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6 &&
                        sscanf(param1, "%02x-%02x-%02x-%02x-%02x-%02x",
                               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
                        err_msg = "Invalid MAC address format";
                    } else {
                        for (int i = 0; i < 6; i++) {
                            mac_bytes[i] = (uint8_t)mac[i];
                        }

                        uint32_t ip = is_block ? 0 : esp_ip4addr_aton(param2);
                        if (!is_block && ip == IPADDR_NONE) {
                            err_msg = "Invalid IP address";
                        } else if (!is_block && (ip & 0x00FFFFFF) != (my_ap_ip & 0x00FFFFFF)) {
                            err_msg = "IP must be in the same network as the AP";
                        } else {
                            const char *name = NULL;
                            if (httpd_query_key_value(form, "dhcp_name", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                                preprocess_string(param3);
                                name = param3;
                            }
                            add_dhcp_reservation(mac_bytes, ip, name);
                            ESP_LOGI(TAG, "Added DHCP reservation: %s -> %s", param1, param2);
                        }
                    }

                    if (err_msg != NULL) {
                        /* Redirect back with error parameter */
                        char redirect_url[128];
                        snprintf(redirect_url, sizeof(redirect_url), "/mappings?error=%s", err_msg);
                        for (char *p = redirect_url; *p; p++) {
                            if (*p == ' ') *p = '+';
                        }
                        httpd_resp_set_status(req, "303 See Other");
                        httpd_resp_set_hdr(req, "Location", redirect_url);
                        httpd_resp_send(req, NULL, 0);
                        free(form);
                        return ESP_OK;
                    }
                }
            }
        }

        /* Check for delete DHCP reservation */
        if (httpd_query_key_value(form, "del_dhcp_mac", param1, sizeof(param1)) == ESP_OK) {
            preprocess_string(param1);
            unsigned int mac[6];
            if (sscanf(param1, "%02X:%02X:%02X:%02X:%02X:%02X",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ||
                sscanf(param1, "%02x:%02x:%02x:%02x:%02x:%02x",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                uint8_t mac_bytes[6];
                for (int i = 0; i < 6; i++) {
                    mac_bytes[i] = (uint8_t)mac[i];
                }
                del_dhcp_reservation(mac_bytes);
                ESP_LOGI(TAG, "Deleted DHCP reservation: %s", param1);
            }
        }

        /* Check for add port mapping */
        if (httpd_query_key_value(form, "port_action", param1, sizeof(param1)) == ESP_OK) {
            if (strcmp(param1, "Add+Forward") == 0 || strcmp(param1, "Add Forward") == 0) {
                if (httpd_query_key_value(form, "proto", param1, sizeof(param1)) == ESP_OK &&
                    httpd_query_key_value(form, "ext_port", param2, sizeof(param2)) == ESP_OK &&
                    httpd_query_key_value(form, "int_ip", param3, sizeof(param3)) == ESP_OK &&
                    httpd_query_key_value(form, "int_port", param4, sizeof(param4)) == ESP_OK) {

                    preprocess_string(param3);
                    uint8_t proto = (strcmp(param1, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
                    uint16_t ext_port = atoi(param2);
                    uint32_t int_ip = esp_ip4addr_aton(param3);

                    /* If IP parsing failed, try resolving as device name */
                    if (int_ip == IPADDR_NONE) {
                        if (!resolve_device_name_to_ip(param3, &int_ip)) {
                            ESP_LOGW(TAG, "Invalid IP or device name: %s", param3);
                        }
                    }
                    uint16_t int_port = atoi(param4);

                    /* Validate internal IP is in same /24 network as AP interface */
                    const char *err_msg = NULL;
                    if (int_ip == IPADDR_NONE) {
                        err_msg = "Invalid IP address or device name";
                    } else if ((int_ip & 0x00FFFFFF) != (my_ap_ip & 0x00FFFFFF)) {
                        esp_ip4_addr_t ap_addr;
                        ap_addr.addr = my_ap_ip;
                        ESP_LOGW(TAG, "Internal IP not in AP network (" IPSTR "/24)", IP2STR(&ap_addr));
                        err_msg = "Internal IP must be in the same network as the AP";
                    } else {
                        /* Check if external port is already in use for this protocol */
                        for (int i = 0; i < IP_PORTMAP_MAX; i++) {
                            if (portmap_tab[i].valid &&
                                portmap_tab[i].proto == proto &&
                                portmap_tab[i].mport == ext_port) {
                                ESP_LOGW(TAG, "External port %d already mapped", ext_port);
                                err_msg = "External port is already in use";
                                break;
                            }
                        }
                    }

                    if (err_msg == NULL) {
                        uint8_t iface = 0;  // Default: STA
                        char iface_param[8];
                        if (httpd_query_key_value(form, "iface", iface_param, sizeof(iface_param)) == ESP_OK) {
                            if (strcmp(iface_param, "VPN") == 0) iface = 1;
                        }
                        add_portmap(proto, ext_port, int_ip, int_port, iface);
#if CONFIG_ETH_UPLINK
                        ESP_LOGI(TAG, "Added port mapping: %s %s %d -> %s:%d",
                                 iface ? "VPN" : "ETH", param1, ext_port, param3, int_port);
#else
                        ESP_LOGI(TAG, "Added port mapping: %s %s %d -> %s:%d",
                                 iface ? "VPN" : "STA", param1, ext_port, param3, int_port);
#endif
                    } else {
                        /* Redirect back with error parameter */
                        char redirect_url[128];
                        snprintf(redirect_url, sizeof(redirect_url), "/mappings?error=%s", err_msg);
                        /* URL encode spaces */
                        for (char *p = redirect_url; *p; p++) {
                            if (*p == ' ') *p = '+';
                        }
                        httpd_resp_set_status(req, "303 See Other");
                        httpd_resp_set_hdr(req, "Location", redirect_url);
                        httpd_resp_send(req, NULL, 0);
                        free(form);
                        return ESP_OK;
                    }
                }
            }
        }

        /* Check for delete port mapping */
        if (httpd_query_key_value(form, "del_proto", param1, sizeof(param1)) == ESP_OK &&
            httpd_query_key_value(form, "del_port", param2, sizeof(param2)) == ESP_OK) {
            uint8_t proto = (strcmp(param1, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
            uint16_t port = atoi(param2);
            del_portmap(proto, port);
            ESP_LOGI(TAG, "Deleted port mapping: %s %d", param1, port);
        }
        free(form);
    }

    /* Reusable buffers.  Stack, not heap: a SEND_CHUNK bail-out on a dead
     * client returns immediately and would leak a heap allocation.  A row holds
     * an escaped device name twice over (once in a cell, once in a data-*
     * attribute), and html_escape() spends up to five bytes per character. */
    char row[768];
    char esc[DHCP_RESERVATION_NAME_LEN * 6];
    int n;

    httpd_resp_set_type(req, "text/html");

    if (send_page_head(req, "Mappings", TAB_MAPPINGS,
                       session_active && password_protection_enabled) != ESP_OK) {
        return ESP_FAIL;
    }

    if (error_msg[0] != '\0') {
        n = snprintf(row, sizeof(row), MAPPINGS_ERROR, error_msg);
        SEND_RENDERED(req, row, n);
    }

    /* Connected clients ---------------------------------------------------- */

    SEND_CHUNK(req, MAPPINGS_CLIENTS_OPEN, HTTPD_RESP_USE_STRLEN);
    if (client_stats_enabled) {
        SEND_CHUNK(req, MAPPINGS_CLIENTS_TRAFFIC, HTTPD_RESP_USE_STRLEN);
    }
    SEND_CHUNK(req, MAPPINGS_CLIENTS_HEAD_END, HTTPD_RESP_USE_STRLEN);

    #define MAX_DISPLAYED_CLIENTS 8
    connected_client_t clients[MAX_DISPLAYED_CLIENTS];
    int client_count = get_connected_clients(clients, MAX_DISPLAYED_CLIENTS);
    connect_count = client_count;

    /* Fetch per-client traffic stats only when enabled */
    client_stats_entry_t stats[CLIENT_STATS_MAX];
    int stats_count = client_stats_enabled ? client_stats_get_all(stats, CLIENT_STATS_MAX) : 0;

    for (int i = 0; i < client_count; i++) {
        char ip_str[16] = "";
        if (clients[i].has_ip) {
            esp_ip4_addr_t addr;
            addr.addr = clients[i].ip;
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&addr));
        }

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            clients[i].mac[0], clients[i].mac[1],
            clients[i].mac[2], clients[i].mac[3],
            clients[i].mac[4], clients[i].mac[5]);

        /* The name is a client-supplied hostname or an operator-supplied
         * reservation label; it goes into a cell and into a data-* attribute,
         * both of which the same escaping covers. */
        html_escape_to(esc, sizeof(esc), clients[i].name);

        char traffic[48] = "";
        if (client_stats_enabled) {
            for (int s = 0; s < stats_count; s++) {
                if (memcmp(stats[s].mac, clients[i].mac, 6) == 0) {
                    char tx_buf[12], rx_buf[12];
                    format_bytes_human(stats[s].bytes_sent, tx_buf, sizeof(tx_buf));
                    format_bytes_human(stats[s].bytes_received, rx_buf, sizeof(rx_buf));
                    /* "up/down" rather than a bare pair: the column heading is
                     * dropped when the table reflows on a phone. */
                    snprintf(traffic, sizeof(traffic),
                             "<td>%s up / %s down</td>", tx_buf, rx_buf);
                    break;
                }
            }
            if (traffic[0] == '\0') {
                strcpy(traffic, "<td class=n>no traffic</td>");
            }
        }

        n = snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td>%s"
            "<td class=a><button type=button class=\"b s\" data-m='%s' "
            "data-i='%s' data-n='%s'>Reserve</button></td></tr>",
            mac_str,
            clients[i].has_ip ? ip_str : "no lease",
            esc[0] ? esc : "unnamed",
            traffic,
            mac_str, ip_str, esc);
        SEND_RENDERED(req, row, n);
    }

    if (client_count == 0) {
        n = snprintf(row, sizeof(row), MAPPINGS_CLIENTS_EMPTY,
                     client_stats_enabled ? 5 : 4);
        SEND_RENDERED(req, row, n);
    }

    SEND_CHUNK(req, MAPPINGS_TABLE_CLOSE, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, MAPPINGS_CARD_CLOSE, HTTPD_RESP_USE_STRLEN);

    /* DHCP reservations ---------------------------------------------------- */

    {
        uint32_t start_ip, end_ip;
        get_dhcp_pool_range(my_ap_ip, &start_ip, &end_ip);
        esp_ip4_addr_t start_addr, end_addr;
        start_addr.addr = start_ip;
        end_addr.addr = end_ip;
        char first[16], last[16];
        snprintf(first, sizeof(first), IPSTR, IP2STR(&start_addr));
        snprintf(last, sizeof(last), IPSTR, IP2STR(&end_addr));
        n = snprintf(row, sizeof(row), MAPPINGS_DHCP_OPEN, first, last);
        SEND_RENDERED(req, row, n);
    }

    bool has_reservations = false;
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (!dhcp_reservations[i].valid) continue;
        has_reservations = true;

        /* A reservation with no address is a block entry: the DHCP server
         * refuses that MAC a lease rather than pinning it to an IP. */
        char ip_col[64];
        if (dhcp_reservations[i].ip == 0) {
            strcpy(ip_col, "<span class=\"bd er\">blocked</span>");
        } else {
            esp_ip4_addr_t addr;
            addr.addr = dhcp_reservations[i].ip;
            snprintf(ip_col, sizeof(ip_col), IPSTR, IP2STR(&addr));
        }

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 dhcp_reservations[i].mac[0], dhcp_reservations[i].mac[1],
                 dhcp_reservations[i].mac[2], dhcp_reservations[i].mac[3],
                 dhcp_reservations[i].mac[4], dhcp_reservations[i].mac[5]);

        html_escape_to(esc, sizeof(esc), dhcp_reservations[i].name);

        n = snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td>"
            "<td class=a><form method=post action=/mappings>"
            "<button class=\"b s d\" name=del_dhcp_mac value='%s' "
            "data-c='Delete this reservation?'>Delete</button></form></td></tr>",
            mac_str, ip_col, esc[0] ? esc : "unnamed", mac_str);
        SEND_RENDERED(req, row, n);
    }

    if (!has_reservations) {
        SEND_CHUNK(req, MAPPINGS_DHCP_EMPTY, HTTPD_RESP_USE_STRLEN);
    }

    SEND_CHUNK(req, MAPPINGS_TABLE_CLOSE, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, MAPPINGS_CARD_CLOSE, HTTPD_RESP_USE_STRLEN);
    SEND_CHUNK(req, MAPPINGS_DHCP_FORM, HTTPD_RESP_USE_STRLEN);

    /* Port forwarding ------------------------------------------------------ */

    if (ap_nat_enabled) {
        SEND_CHUNK(req, MAPPINGS_PORTFWD_OPEN, HTTPD_RESP_USE_STRLEN);

        bool has_mappings = false;
        for (int i = 0; i < IP_PORTMAP_MAX; i++) {
            if (!portmap_tab[i].valid) continue;
            has_mappings = true;

            const char *name = lookup_device_name_by_ip(portmap_tab[i].daddr);
            char ip_or_name[DHCP_RESERVATION_NAME_LEN];
            if (name) {
                snprintf(ip_or_name, sizeof(ip_or_name), "%s", name);
            } else {
                esp_ip4_addr_t addr;
                addr.addr = portmap_tab[i].daddr;
                snprintf(ip_or_name, sizeof(ip_or_name), IPSTR, IP2STR(&addr));
            }
            html_escape_to(esc, sizeof(esc), ip_or_name);

            const char *proto = portmap_tab[i].proto == PROTO_TCP ? "TCP" : "UDP";

            n = snprintf(row, sizeof(row),
                "<tr><td>%s %u</td><td>%s:%u</td><td>%s</td>"
                "<td class=a><form method=post action=/mappings>"
                "<input type=hidden name=del_proto value=%s>"
                "<button class=\"b s d\" name=del_port value=%u "
                "data-c='Delete this forward?'>Delete</button></form></td></tr>",
                proto, (unsigned)portmap_tab[i].mport,
                esc, (unsigned)portmap_tab[i].dport,
                portmap_tab[i].iface == 1 ? "VPN" : PORTMAP_IFACE_WAN,
                proto, (unsigned)portmap_tab[i].mport);
            SEND_RENDERED(req, row, n);
        }

        if (!has_mappings) {
            SEND_CHUNK(req, MAPPINGS_PORTFWD_EMPTY, HTTPD_RESP_USE_STRLEN);
        }

        SEND_CHUNK(req, MAPPINGS_TABLE_CLOSE, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, MAPPINGS_CARD_CLOSE, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, MAPPINGS_PORTFWD_FORM, HTTPD_RESP_USE_STRLEN);
    } else {
        SEND_CHUNK(req, MAPPINGS_PORTFWD_OFF, HTTPD_RESP_USE_STRLEN);
    }

    if (send_page_foot(req) != ESP_OK) {
        return ESP_FAIL;
    }

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t mappingsp = {
    .uri       = "/mappings",
    .method    = HTTP_GET,
    .handler   = mappings_get_handler,
};

/* Same function for both verbs: GET renders the page, POST applies the form
 * and then renders it. */
static httpd_uri_t mappingsp_post = {
    .uri       = "/mappings",
    .method    = HTTP_POST,
    .handler   = mappings_get_handler,
};

/* Firewall (ACL) page GET handler */
static esp_err_t firewall_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    /* Check authentication if password protection is enabled */
    bool password_protection_enabled = is_web_password_set();

    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /firewall from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char *form;
    if (!take_form(req, &form)) {
        return ESP_OK;
    }
    bool action_performed = false;
    char error_msg[128] = "";

    /* The error message rides the query string of the redirect that a rejected
     * rule sends; everything that changes state comes out of the POST body. */
    read_error_param(req, error_msg, sizeof(error_msg));

    if (form != NULL) {
        char param[64];

        /* Handle Add Rule */
        if (httpd_query_key_value(form, "acl_action", param, sizeof(param)) == ESP_OK) {
            if (strcmp(param, "Add+Rule") == 0 || strcmp(param, "Add Rule") == 0) {
                char list_str[8], proto_str[8], src_ip_str[32], src_port_str[8];
                char dst_ip_str[32], dst_port_str[8], action_str[8];

                if (httpd_query_key_value(form, "acl_list", list_str, sizeof(list_str)) == ESP_OK &&
                    httpd_query_key_value(form, "proto", proto_str, sizeof(proto_str)) == ESP_OK &&
                    httpd_query_key_value(form, "src_ip", src_ip_str, sizeof(src_ip_str)) == ESP_OK &&
                    httpd_query_key_value(form, "dst_ip", dst_ip_str, sizeof(dst_ip_str)) == ESP_OK &&
                    httpd_query_key_value(form, "action", action_str, sizeof(action_str)) == ESP_OK) {

                    preprocess_string(src_ip_str);
                    preprocess_string(dst_ip_str);

                    uint8_t list_no = atoi(list_str);
                    uint8_t proto = atoi(proto_str);
                    uint8_t action = atoi(action_str);

                    const char *validation_error = NULL;

                    /* Parse source IP (try IP/CIDR first, then device name) */
                    uint32_t src_ip, src_mask;
                    if (strlen(src_ip_str) == 0) {
                        src_ip = 0;
                        src_mask = 0;  /* any */
                    } else if (!acl_parse_ip(src_ip_str, &src_ip, &src_mask)) {
                        /* Try resolving as device name */
                        if (resolve_device_name_to_ip(src_ip_str, &src_ip)) {
                            src_mask = 0xFFFFFFFF;  /* /32 for device names */
                        } else {
                            validation_error = "Invalid source IP address or device name";
                        }
                    }

                    /* Parse destination IP (try IP/CIDR first, then device name) */
                    uint32_t dst_ip, dst_mask;
                    if (validation_error == NULL) {
                        if (strlen(dst_ip_str) == 0) {
                            dst_ip = 0;
                            dst_mask = 0;  /* any */
                        } else if (!acl_parse_ip(dst_ip_str, &dst_ip, &dst_mask)) {
                            /* Try resolving as device name */
                            if (resolve_device_name_to_ip(dst_ip_str, &dst_ip)) {
                                dst_mask = 0xFFFFFFFF;  /* /32 for device names */
                            } else {
                                validation_error = "Invalid destination IP address or device name";
                            }
                        }
                    }

                    /* Parse ports */
                    uint16_t s_port = 0, d_port = 0;
                    if (httpd_query_key_value(form, "src_port", src_port_str, sizeof(src_port_str)) == ESP_OK) {
                        preprocess_string(src_port_str);
                        if (strcmp(src_port_str, "*") != 0 && strlen(src_port_str) > 0) {
                            s_port = atoi(src_port_str);
                        }
                    }
                    if (httpd_query_key_value(form, "dst_port", dst_port_str, sizeof(dst_port_str)) == ESP_OK) {
                        preprocess_string(dst_port_str);
                        if (strcmp(dst_port_str, "*") != 0 && strlen(dst_port_str) > 0) {
                            d_port = atoi(dst_port_str);
                        }
                    }

                    if (validation_error != NULL) {
                        /* Redirect back with error parameter */
                        char redirect_url[192];
                        snprintf(redirect_url, sizeof(redirect_url), "/firewall?error=%s", validation_error);
                        /* URL encode spaces */
                        for (char *p = redirect_url; *p; p++) {
                            if (*p == ' ') *p = '+';
                        }
                        httpd_resp_set_status(req, "303 See Other");
                        httpd_resp_set_hdr(req, "Location", redirect_url);
                        httpd_resp_send(req, NULL, 0);
                        free(form);
                        return ESP_OK;
                    }

                    if (list_no < MAX_ACL_LISTS) {
                        if (acl_add(list_no, src_ip, src_mask, dst_ip, dst_mask, proto, s_port, d_port, action)) {
                            save_acl_rules();
                            ESP_LOGI(TAG, "Added ACL rule to list %d", list_no);
                            action_performed = true;
                        }
                    }
                }
            }
        }

        /* Handle Delete Rule */
        if (httpd_query_key_value(form, "del_acl", param, sizeof(param)) == ESP_OK) {
            uint8_t list_no = atoi(param);
            char idx_str[8];
            if (httpd_query_key_value(form, "del_idx", idx_str, sizeof(idx_str)) == ESP_OK) {
                uint8_t rule_idx = atoi(idx_str);
                if (list_no < MAX_ACL_LISTS && acl_delete(list_no, rule_idx)) {
                    save_acl_rules();
                    ESP_LOGI(TAG, "Deleted ACL rule %d from list %d", rule_idx, list_no);
                    action_performed = true;
                }
            }
        }

        /* Handle Clear List */
        if (httpd_query_key_value(form, "clear_acl", param, sizeof(param)) == ESP_OK) {
            uint8_t list_no = atoi(param);
            if (list_no < MAX_ACL_LISTS) {
                acl_clear(list_no);
                save_acl_rules();
                ESP_LOGI(TAG, "Cleared ACL list %d", list_no);
                action_performed = true;
            }
        }
        free(form);
    }

    /* Redirect after action to prevent duplicate submissions on refresh */
    if (action_performed) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/firewall");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Reusable buffer for building individual elements. Stack, not heap: a
     * SEND_CHUNK bail-out on a dead client returns immediately.  Sized for a
     * rule row holding two fully escaped device names (31 characters each, six
     * bytes apiece in the worst case) plus its markup. */
    char row[768];
    int n;

    httpd_resp_set_type(req, "text/html");

    if (send_page_head(req, "Firewall", TAB_FIREWALL,
                       session_active && password_protection_enabled) != ESP_OK) {
        return ESP_FAIL;
    }

    if (error_msg[0] != '\0') {
        n = snprintf(row, sizeof(row), FIREWALL_ERROR, error_msg);
        SEND_RENDERED(req, row, n);
    }

    SEND_CHUNK(req, FIREWALL_INTRO, HTTPD_RESP_USE_STRLEN);

    /* One card per list.  The rules are copied out under the lock and the lock
     * released before anything is sent: httpd_resp_send_chunk() can block on
     * TCP, and acl_check_packet() takes the same lock from the netif hooks. */
    for (int list_no = 0; list_no < MAX_ACL_LISTS; list_no++) {
        acl_entry_t rules_copy[MAX_ACL_ENTRIES];
        acl_stats_t stats_copy;
        const char* list_desc;

        acl_lock();
        acl_entry_t* rules = acl_get_rules(list_no);
        acl_stats_t* stats = acl_get_stats(list_no);
        list_desc = acl_get_desc(list_no);
        memcpy(rules_copy, rules, sizeof(rules_copy));
        memcpy(&stats_copy, stats, sizeof(stats_copy));
        acl_unlock();

        n = snprintf(row, sizeof(row), FIREWALL_LIST_OPEN,
                     list_desc, list_no,
                     (unsigned long)stats_copy.packets_allowed,
                     (unsigned long)stats_copy.packets_denied,
                     (unsigned long)stats_copy.packets_nomatch);
        SEND_RENDERED(req, row, n);

        int rule_count = 0;
        for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
            if (!rules_copy[i].valid) continue;
            rule_count++;

            const char *proto_str;
            switch (rules_copy[i].proto) {
                case ACL_PROTO_ICMP: proto_str = "ICMP"; break;
                case ACL_PROTO_TCP:  proto_str = "TCP";  break;
                case ACL_PROTO_UDP:  proto_str = "UDP";  break;
                case ACL_PROTO_IP:   proto_str = "Any";  break;
                default:             proto_str = "?";    break;
            }

            /* A /32 rule is shown by device name when one is known, because
             * that is how it was almost certainly entered.  The name comes from
             * a DHCP reservation or a client's own DHCP option 12, so it is
             * escaped on the way into the page. */
            char src_str[DHCP_RESERVATION_NAME_LEN], dst_str[DHCP_RESERVATION_NAME_LEN];
            const char *name = rules_copy[i].s_mask == 0xFFFFFFFF
                             ? lookup_device_name_by_ip(rules_copy[i].src) : NULL;
            if (name) {
                snprintf(src_str, sizeof(src_str), "%s", name);
            } else {
                acl_format_ip(rules_copy[i].src, rules_copy[i].s_mask, src_str, sizeof(src_str));
            }
            name = rules_copy[i].d_mask == 0xFFFFFFFF
                 ? lookup_device_name_by_ip(rules_copy[i].dest) : NULL;
            if (name) {
                snprintf(dst_str, sizeof(dst_str), "%s", name);
            } else {
                acl_format_ip(rules_copy[i].dest, rules_copy[i].d_mask, dst_str, sizeof(dst_str));
            }

            char src_esc[DHCP_RESERVATION_NAME_LEN * 6], dst_esc[DHCP_RESERVATION_NAME_LEN * 6];
            html_escape_to(src_esc, sizeof(src_esc), src_str);
            html_escape_to(dst_esc, sizeof(dst_esc), dst_str);

            /* Port 0 means "any" in a rule; ':any' reads as an endpoint where a
             * bare '*' next to an address does not. */
            char s_port_str[8], d_port_str[8];
            if (rules_copy[i].s_port == 0) strcpy(s_port_str, "any");
            else snprintf(s_port_str, sizeof(s_port_str), "%u", (unsigned)rules_copy[i].s_port);
            if (rules_copy[i].d_port == 0) strcpy(d_port_str, "any");
            else snprintf(d_port_str, sizeof(d_port_str), "%u", (unsigned)rules_copy[i].d_port);

            const char *action_str;
            uint8_t action = rules_copy[i].allow & 0x01;
            uint8_t monitor = rules_copy[i].allow & ACL_MONITOR;
            if (action == ACL_ALLOW) {
                action_str = monitor ? "Allow, capture" : "Allow";
            } else {
                action_str = monitor ? "Deny, capture" : "Deny";
            }

            /* "hits" is spelled out because the column headings disappear when
             * the table reflows on a phone. */
            n = snprintf(row, sizeof(row),
                "<tr><td>%s:%s</td><td>%s:%s</td><td>%s</td>"
                "<td><span class=\"bd %s\">%s</span></td><td>%lu hits</td>"
                "<td class=a><form method=post action=/firewall>"
                "<input type=hidden name=del_acl value=%d>"
                "<button class=\"b s d\" name=del_idx value=%d "
                "data-c='Delete this rule?'>Delete</button></form></td></tr>",
                src_esc, s_port_str, dst_esc, d_port_str, proto_str,
                action == ACL_ALLOW ? "ok" : "er", action_str,
                (unsigned long)rules_copy[i].hit_count,
                list_no, i);
            SEND_RENDERED(req, row, n);
        }

        if (rule_count == 0) {
            SEND_CHUNK(req, FIREWALL_LIST_EMPTY, HTTPD_RESP_USE_STRLEN);
        }

        SEND_CHUNK(req, FIREWALL_LIST_CLOSE, HTTPD_RESP_USE_STRLEN);
    }

    SEND_CHUNK(req, FIREWALL_ADD_OPEN, HTTPD_RESP_USE_STRLEN);
    for (int list_no = 0; list_no < MAX_ACL_LISTS; list_no++) {
        n = snprintf(row, sizeof(row), FIREWALL_ADD_OPTION,
                     list_no, acl_get_desc(list_no));
        SEND_RENDERED(req, row, n);
    }
    SEND_CHUNK(req, FIREWALL_ADD_REST, HTTPD_RESP_USE_STRLEN);

    if (send_page_foot(req) != ESP_OK) {
        return ESP_FAIL;
    }

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t firewallp = {
    .uri       = "/firewall",
    .method    = HTTP_GET,
    .handler   = firewall_get_handler,
};

/* Same function for both verbs: GET renders the page, POST applies the form
 * and then renders it. */
static httpd_uri_t firewallp_post = {
    .uri       = "/firewall",
    .method    = HTTP_POST,
    .handler   = firewall_get_handler,
};

/* Helper function to convert auth mode to string for web UI */
static const char* web_auth_mode_to_str(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN:            return "Open";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Ent";
        default:                        return "Unknown";
    }
}

/* URL encode a string for use in query parameters */
static void url_encode(const char *src, char *dst, size_t dst_len)
{
    const char *hex = "0123456789ABCDEF";
    size_t i = 0;

    while (*src && i < dst_len - 1) {
        if ((*src >= 'A' && *src <= 'Z') ||
            (*src >= 'a' && *src <= 'z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dst[i++] = *src;
        } else if (i + 3 < dst_len) {
            dst[i++] = '%';
            dst[i++] = hex[(*src >> 4) & 0x0F];
            dst[i++] = hex[*src & 0x0F];
        } else {
            break;
        }
        src++;
    }
    dst[i] = '\0';
}

#if !CONFIG_ETH_UPLINK
/* WiFi Scan page GET handler - NOT password protected */
static esp_err_t scan_get_handler(httpd_req_t *req)
{
    /* Check if user can connect (authenticated or no password set) */
    bool password_protection_enabled = is_web_password_set();
    bool can_connect = !password_protection_enabled || is_authenticated(req);

    uint16_t ap_count = 0;
    wifi_ap_record_t *ap_list = NULL;
    bool scan_in_progress = false;

    /* Suppress STA reconnect attempts while on the scan page */
    if (!ap_connect) {
        wifi_scan_active = true;
    }

    /* Try to get existing scan results first */
    esp_err_t err = esp_wifi_scan_get_ap_num(&ap_count);

    if (err == ESP_OK && ap_count > 0) {
        /* We have results from a previous scan - read them */
        if (ap_count > 20) ap_count = 20;
        ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
        if (ap_list != NULL) {
            esp_wifi_scan_get_ap_records(&ap_count, ap_list);
        } else {
            ap_count = 0;
        }
    }

    /* Start a (new) background scan for the next refresh */
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };
    if (!ap_connect) wifi_scan_active = true;
    err = esp_wifi_scan_start(&scan_config, false);  /* Non-blocking */

    if (ap_count == 0 && (err == ESP_OK || err == ESP_ERR_WIFI_STATE)) {
        scan_in_progress = true;
    }

    /* Reload only while a scan is actually running. Once results are on screen
     * the page stays put, instead of the old unconditional 15 s refresh that
     * threw away the scroll position. Sent as a header so the markup and the
     * shared <head> stay untouched; the literals are static because esp_http_server
     * keeps the pointer until the response is sent. */
    if (scan_in_progress) {
        httpd_resp_set_hdr(req, "Refresh", "2");
    }

    /* ap_list is live from here to the free() below, so bail-outs have to
     * release it rather than use SEND_CHUNK's bare return. */
#define SCAN_CHUNK(buf, len) \
    do { \
        if (httpd_resp_send_chunk(req, (buf), (len)) != ESP_OK) { \
            free(ap_list); \
            return ESP_FAIL; \
        } \
    } while (0)

    if (send_page_head(req, "WiFi Scan", TAB_SCAN,
                       can_connect && password_protection_enabled) != ESP_OK) {
        free(ap_list);
        return ESP_FAIL;
    }

    SCAN_CHUNK(SCAN_TABLE_OPEN, HTTPD_RESP_USE_STRLEN);
    if (can_connect) {
        SCAN_CHUNK(SCAN_TABLE_ACTION_TH, HTTPD_RESP_USE_STRLEN);
    }
    SCAN_CHUNK(SCAN_TABLE_MID, HTTPD_RESP_USE_STRLEN);

    if (ap_count == 0) {
        char row[128];
        int n = snprintf(row, sizeof(row), "<tr><td colspan=%d class=n>%s</td></tr>",
                         can_connect ? 5 : 4,
                         scan_in_progress ? "Scanning..." : "No networks found");
        SCAN_CHUNK(row, n);
    } else {
        for (int i = 0; i < ap_count; i++) {
            int rssi = ap_list[i].rssi;

            /* Quality is spelled out rather than drawn, so it survives a
             * screen reader and a monochrome screen; colour only reinforces it. */
            const char *quality_class, *quality;
            if (rssi >= -55)      { quality_class = "ok"; quality = "Excellent"; }
            else if (rssi >= -67) { quality_class = "ok"; quality = "Good";      }
            else if (rssi >= -75) { quality_class = "wn"; quality = "Fair";      }
            else                  { quality_class = "er"; quality = "Weak";      }

            char *safe_ssid = html_escape((const char *)ap_list[i].ssid);
            if (safe_ssid == NULL) {
                safe_ssid = strdup("(unknown)");
                if (safe_ssid == NULL) continue;
            }

            char ch_info[48];
#if WIFI_HAS_5GHZ
            snprintf(ch_info, sizeof(ch_info), "%d <span class=n>&middot; %s</span>",
                     ap_list[i].primary, ap_list[i].primary > 14 ? "5 GHz" : "2.4 GHz");
#else
            snprintf(ch_info, sizeof(ch_info), "%d", ap_list[i].primary);
#endif

            char row[512];
            int n = snprintf(row, sizeof(row),
                "<tr><td>%s</td>"
                "<td><span class=\"bd %s\">%s</span> <span class=n>%d dBm</span></td>"
                "<td>%s</td><td>%s</td>",
                safe_ssid[0] ? safe_ssid : "<span class=n>(hidden)</span>",
                quality_class, quality, rssi,
                ch_info,
                web_auth_mode_to_str(ap_list[i].authmode));
            free(safe_ssid);
            if (n > 0) {
                SCAN_CHUNK(row, n);
            }

            if (can_connect) {
                char encoded_ssid[128];
                char cell[192];
                url_encode((const char *)ap_list[i].ssid, encoded_ssid, sizeof(encoded_ssid));
                /* class=a marks the action cell so the narrow-screen reflow
                 * keeps it on its own line instead of folding it into the
                 * run-on detail line. */
                n = snprintf(cell, sizeof(cell),
                             "<td class=a><a class=\"b s\" href=/setup?ssid=%s>Connect</a></td>",
                             encoded_ssid);
                SCAN_CHUNK(cell, n);
            }
            SCAN_CHUNK("</tr>", 5);
        }
    }

    free(ap_list);
    ap_list = NULL;
#undef SCAN_CHUNK

    SEND_CHUNK(req, SCAN_TABLE_CLOSE, HTTPD_RESP_USE_STRLEN);
    send_page_foot(req);
    return httpd_resp_send_chunk(req, NULL, 0);
}

static httpd_uri_t scanp = {
    .uri       = "/scan",
    .method    = HTTP_GET,
    .handler   = scan_get_handler,
};
#endif

#if !CONFIG_ETH_UPLINK
/* Getting Started page GET handler */
static esp_err_t setup_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    /* Check authentication if password protection is enabled */
    if (is_web_password_set() && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /setup from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char *form;
    if (!take_form(req, &form)) {
        return ESP_OK;
    }

    char param1[64], param2[64];

    /* Set when this request armed the restart timer, so the page can say so
     * instead of a script guessing from the query string. */
    bool restarting = false;

    if (form != NULL) {

        /* Handle AP settings */
        if (httpd_query_key_value(form, "ap_ssid", param1, sizeof(param1)) == ESP_OK) {
            preprocess_string(param1);
            if (httpd_query_key_value(form, "ap_password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param2);
                if (strlen(param2) == 0) {
                    strlcpy(param2, ap_passwd, sizeof(param2));
                }

                /* Reset AP parameters to defaults (keep SSID/password from form) */
                set_config_param_str("ap_ip",      DEFAULT_AP_IP);
                set_config_param_str("ap_dns",     "");
                free(ap_dns); ap_dns = strdup("");
                set_config_param_int("ap_hidden",   0); ap_ssid_hidden = 0;
                set_config_param_int("ap_authmode", 0); ap_authmode    = 0;
                set_config_param_int("ap_disabled", 0); ap_disabled    = false;
                set_config_param_int("ap_nat",      1); ap_nat_enabled = 1;

                int argc = 3;
                char* argv[3];
                argv[0] = "set_ap";
                argv[1] = param1;
                argv[2] = param2;
                set_ap(argc, argv);
            }
        }

#if !CONFIG_ETH_UPLINK
        /* Handle STA settings */
        if (httpd_query_key_value(form, "ssid", param1, sizeof(param1)) == ESP_OK) {
            preprocess_string(param1);
            if (httpd_query_key_value(form, "password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param2);
                if (strlen(param2) == 0) {
                    strlcpy(param2, passwd, sizeof(param2));
                }

                /* Reset STA parameters to defaults (keep SSID/password from form) */
                set_config_param_str("static_ip",    ""); free(static_ip);   static_ip   = strdup("");
                set_config_param_str("subnet_mask",  ""); free(subnet_mask); subnet_mask = strdup("");
                set_config_param_str("gateway_addr", ""); free(gateway_addr); gateway_addr = strdup("");
                set_config_param_str("ent_username", ""); free(ent_username); ent_username = strdup("");
                set_config_param_str("ent_identity", ""); free(ent_identity); ent_identity = strdup("");
                set_config_param_int("ttls_phase2", 0); ttls_phase2       = 0;
                set_config_param_int("cert_bundle", 0); use_cert_bundle   = 0;
                set_config_param_int("no_time_chk", 0); disable_time_check = 0;

                int argc = 3;
                char* argv[3];
                argv[0] = "set_sta";
                argv[1] = param1;
                argv[2] = param2;
                set_sta(argc, argv);
                esp_timer_start_once(restart_timer, 500000);
                restarting = true;
            }
        }
#endif
        free(form);
    }

#if !CONFIG_ETH_UPLINK
    /* Check for SSID pre-fill from the scan page.  A read, so it stays on the
     * query string: /setup?ssid=... only fills a field in. */
    char prefill_ssid[64] = "";
    size_t query_len = httpd_req_get_url_query_len(req) + 1;
    if (query_len > 1) {
        char *query = malloc(query_len);
        if (query != NULL) {
            if (httpd_req_get_url_query_str(req, query, query_len) == ESP_OK &&
                httpd_query_key_value(query, "ssid", prefill_ssid, sizeof(prefill_ssid)) == ESP_OK) {
                preprocess_string(prefill_ssid);
            }
            free(query);
        }
    }
#endif

    /* Render page */
    httpd_resp_set_type(req, "text/html");

    send_page_head(req, "Getting Started", TAB_SETUP, is_web_password_set());

    SEND_CHUNK(req, restarting ? SETUP_REBOOT_NOTE : SETUP_INTRO, HTTPD_RESP_USE_STRLEN);

    /* Escape into stack buffers so nothing heap-allocated is held across the
     * SEND_CHUNK calls below (a bail-out on a dead client returns immediately). */
    char safe_ap_ssid[200];
    html_escape_to(safe_ap_ssid, sizeof(safe_ap_ssid), ap_ssid);

    /* Sized for the worst case once the two escaped SSID fields are fixed-size
     * stack buffers; the default 1024 would risk truncation. */
    char section[1536];
    char safe_ssid[200];
    html_escape_to(safe_ssid, sizeof(safe_ssid), prefill_ssid[0] ? prefill_ssid : ssid);
    snprintf(section, sizeof(section), SETUP_CHUNK_FORM, safe_ap_ssid, safe_ssid);
    SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);

    send_page_foot(req);

    SEND_CHUNK(req, NULL, 0);
    return ESP_OK;
}

static httpd_uri_t setupp = {
    .uri       = "/setup",
    .method    = HTTP_GET,
    .handler   = setup_get_handler,
};

/* Same function for both verbs: GET renders the page, POST applies the form
 * and then renders it. */
static httpd_uri_t setupp_post = {
    .uri       = "/setup",
    .method    = HTTP_POST,
    .handler   = setup_get_handler,
};
#endif /* !CONFIG_ETH_UPLINK */

/* VPN page GET handler */
static esp_err_t vpn_get_handler(httpd_req_t *req)
{
    resume_sta_if_scan_idle();
    /* Check authentication if password protection is enabled */
    bool password_protection_enabled = is_web_password_set();

    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /vpn from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char *form;
    if (!take_form(req, &form)) {
        return ESP_OK;
    }
    bool saved = false;

    if (form != NULL) {
        char param[128];

        /* Check if this is a form submission */
        if (httpd_query_key_value(form, "vpn_enabled", param, sizeof(param)) == ESP_OK) {
            saved = true;
            nvs_handle_t nvs;
            if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                nvs_set_i32(nvs, "vpn_enabled", atoi(param));

                if (httpd_query_key_value(form, "vpn_privkey", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    if (param[0] != '\0')
                        nvs_set_str(nvs, "vpn_privkey", param);
                }
                if (httpd_query_key_value(form, "vpn_pubkey", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    nvs_set_str(nvs, "vpn_pubkey", param);
                }
                if (httpd_query_key_value(form, "vpn_psk", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    if (param[0] != '\0')
                        nvs_set_str(nvs, "vpn_psk", param);
                }
                if (httpd_query_key_value(form, "vpn_endpoint", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    nvs_set_str(nvs, "vpn_endpoint", param);
                }
                if (httpd_query_key_value(form, "vpn_port", param, sizeof(param)) == ESP_OK) {
                    nvs_set_i32(nvs, "vpn_port", atoi(param));
                }
                if (httpd_query_key_value(form, "vpn_ip", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    nvs_set_str(nvs, "vpn_ip", param);
                }
                if (httpd_query_key_value(form, "vpn_mask", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    nvs_set_str(nvs, "vpn_mask", param);
                }
                if (httpd_query_key_value(form, "vpn_dns", param, sizeof(param)) == ESP_OK) {
                    preprocess_string(param);
                    nvs_set_str(nvs, "vpn_dns", param);
                }
                if (httpd_query_key_value(form, "vpn_ka", param, sizeof(param)) == ESP_OK) {
                    nvs_set_i32(nvs, "vpn_ka", atoi(param));
                }
                if (httpd_query_key_value(form, "vpn_ks", param, sizeof(param)) == ESP_OK) {
                    nvs_set_i32(nvs, "vpn_ks", atoi(param));
                }
                if (httpd_query_key_value(form, "vpn_rall", param, sizeof(param)) == ESP_OK) {
                    nvs_set_i32(nvs, "vpn_rall", atoi(param));
                }

                nvs_commit(nvs);
                nvs_close(nvs);
                ESP_LOGI(TAG, "VPN settings saved, scheduling restart");
                esp_timer_start_once(restart_timer, 500000);
            }
        }
        free(form);
    }

    /* Reusable buffers for the page rows.
     * Stack, not heap: a SEND_CHUNK bail-out on a dead client returns
     * immediately, and a heap buffer here would leak on every such bail. */
    char row[512];
    char esc[192];
    int n;

    httpd_resp_set_type(req, "text/html");

    if (send_page_head(req, "WireGuard VPN", TAB_VPN,
                       session_active && password_protection_enabled) != ESP_OK) {
        return ESP_FAIL;
    }

    if (saved) {
        SEND_CHUNK(req, VPN_REBOOT_NOTE, HTTPD_RESP_USE_STRLEN);
    }

    /* Status ------------------------------------------------------------- */

    SEND_CHUNK(req, VPN_STATUS_OPEN, HTTPD_RESP_USE_STRLEN);

    {
        /* vpn_is_connected() is the handshake-complete state; vpn_connected is
         * set as soon as the tunnel is brought up, so the two together tell
         * "configured but not talking yet" apart from "down". */
        const char *state, *cls;
        if (!vpn_enabled) {
            state = "Disabled";           cls = "n";
        } else if (vpn_is_connected()) {
            state = "Connected";          cls = "bd ok";
        } else if (vpn_connected) {
            state = "Handshake pending";  cls = "bd wn";
        } else {
            state = "Disconnected";       cls = "bd er";
        }
        n = snprintf(row, sizeof(row),
                     "<tr><td>Tunnel</td><td><span class=\"%s\">%s</span></td></tr>",
                     cls, state);
        SEND_RENDERED(req, row, n);
    }

    if (vpn_address && vpn_address[0]) {
        html_escape_to(esc, sizeof(esc), vpn_address);
        n = snprintf(row, sizeof(row),
                     "<tr><td>Tunnel address</td><td>%s</td></tr>", esc);
        SEND_RENDERED(req, row, n);
    }

    n = snprintf(row, sizeof(row),
                 "<tr><td>MSS clamp</td><td>%u</td></tr>"
                 "<tr><td>Path MTU</td><td>%u</td></tr>"
                 "<tr><td>Kill switch</td><td><span class=\"%s\">%s</span></td></tr>"
                 "<tr><td>Routing</td><td>%s</td></tr>",
                 (unsigned)ap_mss_clamp, (unsigned)ap_pmtu,
                 vpn_killswitch ? "bd ok" : "n", vpn_killswitch ? "On" : "Off",
                 vpn_route_all ? "All traffic" : "Split tunnel");
    SEND_RENDERED(req, row, n);

    SEND_CHUNK(req, VPN_STATUS_CLOSE, HTTPD_RESP_USE_STRLEN);

    /* This router's end of the tunnel -------------------------------------
     *
     * Every value below comes out of NVS, so it is escaped on the way into an
     * attribute: a config import or a console command can put anything at all
     * in these strings. */

    SEND_CHUNK(req, VPN_FORM_OPEN, HTTPD_RESP_USE_STRLEN);

    n = snprintf(row, sizeof(row),
                 "<label for=ve>Enabled</label>"
                 "<select id=ve name=vpn_enabled>"
                 "<option value=1%s>Enabled</option>"
                 "<option value=0%s>Disabled</option></select>",
                 vpn_enabled ? " selected" : "", vpn_enabled ? "" : " selected");
    SEND_RENDERED(req, row, n);

    n = snprintf(row, sizeof(row),
                 "<label for=vk>Private key</label>"
                 "<input id=vk type=password name=vpn_privkey placeholder='%s'>",
                 (vpn_private_key && vpn_private_key[0]) ? "unchanged"
                                                         : "base64 private key");
    SEND_RENDERED(req, row, n);

    html_escape_to(esc, sizeof(esc), vpn_address);
    n = snprintf(row, sizeof(row),
                 "<label for=va>Address</label>"
                 "<input id=va type=text name=vpn_ip value='%s' placeholder='10.2.0.2'>",
                 esc);
    SEND_RENDERED(req, row, n);

    html_escape_to(esc, sizeof(esc), vpn_netmask ? vpn_netmask : "255.255.255.0");
    n = snprintf(row, sizeof(row),
                 "<label for=vm>Netmask</label>"
                 "<input id=vm type=text name=vpn_mask value='%s'>", esc);
    SEND_RENDERED(req, row, n);

    html_escape_to(esc, sizeof(esc), vpn_dns);
    n = snprintf(row, sizeof(row),
                 "<label for=vd>DNS</label>"
                 "<input id=vd type=text name=vpn_dns value='%s' placeholder='optional'>"
                 "<p class=hint>Handed to clients while the tunnel is up.</p>", esc);
    SEND_RENDERED(req, row, n);

    n = snprintf(row, sizeof(row),
                 "<label for=vs>Kill switch</label>"
                 "<select id=vs name=vpn_ks>"
                 "<option value=1%s>On</option><option value=0%s>Off</option></select>"
                 "<p class=hint>Blocks client traffic whenever the tunnel is down.</p>",
                 vpn_killswitch ? " selected" : "", vpn_killswitch ? "" : " selected");
    SEND_RENDERED(req, row, n);

    n = snprintf(row, sizeof(row),
                 "<label for=vr>Routing</label>"
                 "<select id=vr name=vpn_rall>"
                 "<option value=1%s>All traffic</option>"
                 "<option value=0%s>Split tunnel</option></select>",
                 vpn_route_all ? " selected" : "", vpn_route_all ? "" : " selected");
    SEND_RENDERED(req, row, n);

    /* The remote end ------------------------------------------------------ */

    SEND_CHUNK(req, VPN_FORM_MID, HTTPD_RESP_USE_STRLEN);

    html_escape_to(esc, sizeof(esc), vpn_public_key);
    n = snprintf(row, sizeof(row),
                 "<label for=vp>Public key</label>"
                 "<input id=vp type=text name=vpn_pubkey value='%s' "
                 "placeholder='base64 public key'>", esc);
    SEND_RENDERED(req, row, n);

    n = snprintf(row, sizeof(row),
                 "<label for=vq>Preshared key</label>"
                 "<input id=vq type=password name=vpn_psk placeholder='%s'>",
                 (vpn_preshared_key && vpn_preshared_key[0]) ? "unchanged" : "optional");
    SEND_RENDERED(req, row, n);

    html_escape_to(esc, sizeof(esc), vpn_endpoint);
    n = snprintf(row, sizeof(row),
                 "<label for=vh>Endpoint</label>"
                 "<input id=vh type=text name=vpn_endpoint value='%s' "
                 "placeholder='host or IP'>"
                 "<label for=vo>Port</label>"
                 "<input id=vo type=number name=vpn_port value='%d' min=1 max=65535>",
                 esc, (int)vpn_port);
    SEND_RENDERED(req, row, n);

    n = snprintf(row, sizeof(row),
                 "<label for=vka>Keepalive</label>"
                 "<input id=vka type=number name=vpn_ka value='%d' min=0 max=65535>"
                 "<p class=hint>Seconds between keepalives; 0 disables them.</p>",
                 (int)vpn_keepalive);
    SEND_RENDERED(req, row, n);

    SEND_CHUNK(req, VPN_FORM_CLOSE, HTTPD_RESP_USE_STRLEN);

    SEND_CHUNK(req, VPN_IMPORT, HTTPD_RESP_USE_STRLEN);

    if (send_page_foot(req) != ESP_OK) {
        return ESP_FAIL;
    }

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t vpnp = {
    .uri       = "/vpn",
    .method    = HTTP_GET,
    .handler   = vpn_get_handler,
};

/* Same function for both verbs: GET renders the page, POST applies the form
 * and then renders it. */
static httpd_uri_t vpnp_post = {
    .uri       = "/vpn",
    .method    = HTTP_POST,
    .handler   = vpn_get_handler,
};

static esp_err_t captive_redirect_handler(httpd_req_t *req, httpd_err_code_t err);

httpd_handle_t start_webserver(uint16_t port)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.stack_size = 16384;  // Large stack needed for mappings page with 3x 2KB HTML buffers
    /* Pages (each settings page twice: GET to render, POST to apply), the JSON
     * APIs, and the three static assets (/app.css, /app.js, /favicon.svg plus
     * the /favicon.png alias). Registration fails silently past this limit, so
     * it has to stay ahead of the list below. */
    config.max_uri_handlers = 24;
    config.max_uri_len = 1024;
    config.open_fn = http_open_fn;
    /* Fail a stalled send/recv fast (default 5s) so an abandoned connection
     * frees its socket and buffers quickly instead of pinning them; paired
     * with the SEND_CHUNK bail-out, a dead client costs ~one timeout total. */
    config.send_wait_timeout = 2;
    config.recv_wait_timeout = 2;
    /* A WiFi client that just walks out of range never sends a TCP FIN, so its
     * connections sit in httpd's socket table forever, each pinning a netconn +
     * PCB + pbufs (the few-KB-per-disconnect leak).  After a few rounds the table
     * fills and accept() fails with ENFILE (errno 23).  lru_purge_enable lets
     * httpd close the least-recently-used connection to admit a new one, so the
     * server always recovers; the keepalive probes set in http_open_fn reap the
     * dead sockets proactively before it ever comes to that. */
    config.lru_purge_enable = true;

    /* Load web UI interface bind mask from NVS */
    {
        int bind_val = (int)(RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN);
        get_config_param_int("web_bind", &bind_val);
        s_web_bind = (uint8_t)(bind_val & (RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN));
        if (s_web_bind == 0) s_web_bind = RC_BIND_AP;
    }

    esp_timer_create(&restart_timer_args, &restart_timer);

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &indexp);
        httpd_register_uri_handler(server, &indexp_post);
        httpd_register_uri_handler(server, &configp);
        httpd_register_uri_handler(server, &configp_post);
        httpd_register_uri_handler(server, &mappingsp);
        httpd_register_uri_handler(server, &mappingsp_post);
        httpd_register_uri_handler(server, &firewallp);
        httpd_register_uri_handler(server, &firewallp_post);
#if !CONFIG_ETH_UPLINK
        httpd_register_uri_handler(server, &scanp);
#endif
        httpd_register_uri_handler(server, &vpnp);
        httpd_register_uri_handler(server, &vpnp_post);
#if !CONFIG_ETH_UPLINK
        httpd_register_uri_handler(server, &setupp);
        httpd_register_uri_handler(server, &setupp_post);
#endif
        httpd_register_uri_handler(server, &favicon_uri);
        httpd_register_uri_handler(server, &favicon_png_uri);
        httpd_register_uri_handler(server, &app_css_uri);
        httpd_register_uri_handler(server, &app_js_uri);
        httpd_register_uri_handler(server, &config_exportp);
        httpd_register_uri_handler(server, &config_importp);
        httpd_register_uri_handler(server, &vpn_importp);
        httpd_register_uri_handler(server, &ota_uploadp);

#if CONFIG_ETH_UPLINK
        // In ETH mode, start captive portal if router appears unconfigured
        if (strlen(ap_passwd) == 0 && !is_web_password_set()) {
            ESP_LOGI(TAG, "No AP/web password set, starting captive portal DNS");
            httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, captive_redirect_handler);
            web_server_start_captive_dns();
        }
#else
        // Start captive portal DNS only when no upstream WiFi is configured
        if (ssid == NULL || strlen(ssid) == 0) {
            ESP_LOGI(TAG, "No STA configured, starting captive portal DNS");
            httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, captive_redirect_handler);
            web_server_start_captive_dns();
        }
#endif

        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

// ---------- Captive portal ----------

// DNS server: resolve every query to the AP IP so captive-portal checks succeed
static void dns_server_task(void *pvParameters)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS server: socket failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "DNS server: bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Captive portal DNS server started");
    uint8_t buf[512];

    /* Bytes appended after the received query to form the A-record answer:
     * name pointer (2) + type (2) + class (2) + TTL (4) + RDLENGTH (2) + IPv4 (4) */
    #define DNS_ANSWER_LEN 16

    while (1) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int len = recvfrom(sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&client, &client_len);
        if (len < 12) continue;

        /* Drop oversized queries: the appended answer must fit in buf.
         * Without this, a >=496-byte packet overflows the stack buffer. */
        if (len > (int)sizeof(buf) - DNS_ANSWER_LEN) continue;

        /* Only respond to standard queries: QR=0 (query) and exactly one question. */
        if (buf[2] & 0x80) continue;                  // QR bit set => not a query
        if (buf[4] != 0x00 || buf[5] != 0x01) continue; // QDCOUNT != 1

        // Turn query into response
        buf[2] = 0x81;  // QR=1, AA=1, RD=1
        buf[3] = 0x80;  // RA=1
        buf[6] = 0x00;  buf[7] = 0x01;  // 1 answer

        // Append A record: name-pointer, type A, class IN, TTL 60, AP IP
        uint8_t *ip_bytes = (uint8_t *)&my_ap_ip;
        int pos = len;
        buf[pos++] = 0xC0; buf[pos++] = 0x0C;
        buf[pos++] = 0x00; buf[pos++] = 0x01;
        buf[pos++] = 0x00; buf[pos++] = 0x01;
        buf[pos++] = 0x00; buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0x3C;
        buf[pos++] = 0x00; buf[pos++] = 0x04;
        buf[pos++] = ip_bytes[0]; buf[pos++] = ip_bytes[1];
        buf[pos++] = ip_bytes[2]; buf[pos++] = ip_bytes[3];

        sendto(sock, buf, pos, 0,
               (struct sockaddr *)&client, client_len);
    }
}

void web_server_start_captive_dns(void)
{
    xTaskCreate(dns_server_task, "dns_srv", 4096, NULL, 5, NULL);
}

// 404 handler: redirect unknown URIs to the main page (captive portal trigger)
static char captive_redirect_url[32];

static esp_err_t captive_redirect_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (captive_redirect_url[0] == '\0') {
        snprintf(captive_redirect_url, sizeof(captive_redirect_url),
                 "http://" IPSTR "/", IP2STR((esp_ip4_addr_t *)&my_ap_ip));
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", captive_redirect_url);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}
