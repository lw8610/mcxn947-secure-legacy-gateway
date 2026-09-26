/* SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors */
/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include "ca_certificate.h"
#include "html_stream.h"
#include "proxy_request.h"
#if defined(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)
#include "els_psa_selftest.h"
#endif

#define AAA_CA_CERTIFICATE_TAG 2
#define ISRG_ROOT_X1_TAG 3
#define GLOBALSIGN_ROOT_R3_TAG 4
#define SECOM_ROOT_CA2_TAG 5
#define DIGICERT_GLOBAL_ROOT_G2_TAG 6
#define DIGICERT_GLOBAL_ROOT_G3_TAG 7

static const unsigned char aaa_ca_certificate[] = {
#include "aaa_certificate_services.der.inc"
};

static const unsigned char isrg_root_x1[] = {
#include "isrg_root_x1.der.inc"
};

static const unsigned char globalsign_root_r3[] = {
#include "globalsign_root_r3.der.inc"
};

/* Security Communication RootCA2, obtained from SECOM's official
 * repository. SHA-256: 513B2CECB810D4CDE5DD85391ADFC6C2DD60D87BB736D2B521484AA47A0EBEF6 */
static const unsigned char secom_root_ca2[] = {
#include "secom_root_ca2.der.inc"
};

/* DigiCert Global Root G2, obtained from DigiCert's official repository.
 * SHA-256: CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F */
static const unsigned char digicert_global_root_g2[] = {
#include "digicert_global_root_g2.der.inc"
};

/* DigiCert Global Root G3, obtained from DigiCert's official repository.
 * SHA-256: 31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0 */
static const unsigned char digicert_global_root_g3[] = {
#include "digicert_global_root_g3.der.inc"
};

static const sec_tag_t trusted_ca_tags[] = {
    CA_CERTIFICATE_TAG,
    AAA_CA_CERTIFICATE_TAG,
    ISRG_ROOT_X1_TAG,
    GLOBALSIGN_ROOT_R3_TAG,
    SECOM_ROOT_CA2_TAG,
    DIGICERT_GLOBAL_ROOT_G2_TAG,
    DIGICERT_GLOBAL_ROOT_G3_TAG,
};

static const sec_tag_t isrg_root_x1_tags[] = {
    ISRG_ROOT_X1_TAG,
};

static const sec_tag_t globalsign_root_r1_tags[] = {
    CA_CERTIFICATE_TAG,
};

struct trusted_ca {
    sec_tag_t tag;
    const unsigned char *certificate;
    size_t size;
    const char *name;
};

static const struct trusted_ca trusted_cas[] = {
    {CA_CERTIFICATE_TAG, ca_certificate, sizeof(ca_certificate),
     "GlobalSign Root R1"},
    {AAA_CA_CERTIFICATE_TAG, aaa_ca_certificate,
     sizeof(aaa_ca_certificate), "AAA Certificate Services"},
    {ISRG_ROOT_X1_TAG, isrg_root_x1, sizeof(isrg_root_x1),
     "ISRG Root X1"},
    {GLOBALSIGN_ROOT_R3_TAG, globalsign_root_r3,
     sizeof(globalsign_root_r3), "GlobalSign Root R3"},
    {SECOM_ROOT_CA2_TAG, secom_root_ca2,
     sizeof(secom_root_ca2), "Security Communication RootCA2"},
    {DIGICERT_GLOBAL_ROOT_G2_TAG, digicert_global_root_g2,
     sizeof(digicert_global_root_g2), "DigiCert Global Root G2"},
    {DIGICERT_GLOBAL_ROOT_G3_TAG, digicert_global_root_g3,
     sizeof(digicert_global_root_g3), "DigiCert Global Root G3"},
};

LOG_MODULE_REGISTER(mcx_gateway, LOG_LEVEL_INF);

#define LOCAL_PORT 8080
#define CLIENT_REQUEST_TIMEOUT_SEC 5
#define CLIENT_SEND_TIMEOUT_SEC 10
#define UPSTREAM_IO_TIMEOUT_SEC 15
#define TLS_SOCKET_CREATE_ATTEMPTS 5
#define TLS_SOCKET_RETRY_MS 100
#define PROXY_WORKER_COUNT 2
#define PROXY_WORKER_STACK_SIZE 8192
/* Keep a bounded backlog for browsers which fetch several page assets in
 * parallel. Excess connections are still closed without blocking accept(). */
#define CLIENT_QUEUE_DEPTH 4

static struct net_mgmt_event_callback dhcp_event_callback;

static void log_ipv4_config(struct net_if *iface, const char *reason)
{
    char address[NET_IPV4_ADDR_LEN];
    char netmask[NET_IPV4_ADDR_LEN];
    char gateway[NET_IPV4_ADDR_LEN];

    if (iface == NULL || iface->config.ip.ipv4 == NULL) {
        LOG_WRN("%s: IPv4 interface is not ready", reason);
        return;
    }

    for (size_t i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
        struct net_if_addr *if_addr =
            &iface->config.ip.ipv4->unicast[i].ipv4;

        if (!if_addr->is_used) {
            continue;
        }

        const char *source = if_addr->addr_type == NET_ADDR_DHCP ?
                             "DHCP" : "static";

        LOG_INF("%s IPv4 (%s): %s", reason, source,
                net_addr_ntop(AF_INET, &if_addr->address.in_addr,
                              address, sizeof(address)));
        LOG_INF("IPv4 netmask: %s",
                net_addr_ntop(AF_INET,
                              &iface->config.ip.ipv4->unicast[i].netmask,
                              netmask, sizeof(netmask)));
        LOG_INF("IPv4 gateway: %s",
                net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw,
                              gateway, sizeof(gateway)));
        return;
    }

    LOG_WRN("%s: no IPv4 address is active", reason);
}

static void dhcp_bound_handler(struct net_mgmt_event_callback *callback,
                               uint64_t event, struct net_if *iface)
{
    ARG_UNUSED(callback);
    ARG_UNUSED(event);

    log_ipv4_config(iface, "DHCP bound");
}

static int set_socket_timeout(int sock, int option, int seconds,
                              const char *description)
{
    struct timeval timeout = {
        .tv_sec = seconds,
        .tv_usec = 0,
    };
    int ret = zsock_setsockopt(sock, SOL_SOCKET, option,
                               &timeout, sizeof(timeout));
    if (ret < 0) {
        int error = errno;
        LOG_ERR("Could not set %s timeout: %d", description, error);
        return -error;
    }

    return 0;
}

static int send_all(int sock, const char *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        int ret = zsock_send(sock, buf + sent, len - sent, 0);

        if (ret <= 0) {
            int error = ret < 0 ? errno : EIO;
            if (error != EPIPE && error != ECONNRESET &&
                error != ECONNABORTED && error != ENOTCONN &&
                error != EAGAIN && error != ETIMEDOUT &&
                error != ENOBUFS && error != ENOMEM) {
                LOG_ERR("send_all failed: socket %d, errno %d, sent %zu/%zu bytes",
                        sock, error, sent, len);
            }
            return -error;
        }

        sent += ret;
    }

    return 0;
}

static bool peer_closed_result(int ret)
{
    return ret == -EPIPE || ret == -ECONNRESET ||
           ret == -ECONNABORTED || ret == -ENOTCONN;
}

static bool client_write_timeout_result(int ret)
{
    return ret == -EAGAIN || ret == -ETIMEDOUT ||
           ret == -ENOBUFS || ret == -ENOMEM;
}


#define RESPONSE_HEADER_SIZE 4096
#define HTTPS_REQUEST_SIZE (PROXY_HOST_SIZE + PROXY_PATH_SIZE + \
                            PROXY_USER_AGENT_SIZE + 192)

struct proxy_worker {
    unsigned int id;
    char response_header[RESPONSE_HEADER_SIZE];
    char request_header[PROXY_REQUEST_HEADER_SIZE + 1];
    char https_request[HTTPS_REQUEST_SIZE];
    struct proxy_request parsed_request;
};

K_MSGQ_DEFINE(client_queue, sizeof(int), CLIENT_QUEUE_DEPTH, sizeof(int));
K_THREAD_STACK_ARRAY_DEFINE(proxy_worker_stacks, PROXY_WORKER_COUNT,
                            PROXY_WORKER_STACK_SIZE);
static struct k_thread proxy_worker_threads[PROXY_WORKER_COUNT];
static struct proxy_worker proxy_workers[PROXY_WORKER_COUNT];
/* The configured Mbed TLS memory-buffer allocator is global. Serialize each
 * TLS library call while still allowing workers to wait on legacy clients
 * independently between TLS calls. */
K_MUTEX_DEFINE(tls_operation_lock);

static int install_trusted_cas(void)
{
    for (size_t i = 0; i < sizeof(trusted_cas) / sizeof(trusted_cas[0]); i++) {
        int ret = tls_credential_add(trusted_cas[i].tag,
                                     TLS_CREDENTIAL_CA_CERTIFICATE,
                                     trusted_cas[i].certificate,
                                     trusted_cas[i].size);
        if (ret < 0 && ret != -EEXIST) {
            LOG_ERR("Could not install %s: %d", trusted_cas[i].name, ret);
            return ret;
        }
    }

    LOG_INF("Installed %zu trusted CA roots",
            sizeof(trusted_cas) / sizeof(trusted_cas[0]));
    return 0;
}

static bool header_name(const char *line, const char *end, const char *name)
{
    size_t len = strlen(name);
    return (size_t)(end - line) > len && line[len] == ':' &&
           strncasecmp(line, name, len) == 0;
}

static bool dns_name_matches(const char *host, const char *domain)
{
    size_t host_length = strlen(host);
    size_t domain_length = strlen(domain);

    if (host_length < domain_length ||
        strcasecmp(host + host_length - domain_length, domain) != 0) {
        return false;
    }

    return host_length == domain_length ||
           host[host_length - domain_length - 1] == '.';
}

static size_t trusted_tags_for_host(const char *host,
                                    const sec_tag_t **tags)
{
    /* Wikimedia currently uses a long Let's Encrypt chain. Passing only its
     * required root avoids parsing every unrelated root in both TLS workers. */
    if (dns_name_matches(host, "wikipedia.org") ||
        dns_name_matches(host, "wikimedia.org") ||
        dns_name_matches(host, "mediawiki.org") ||
        dns_name_matches(host, "wmfusercontent.org") ||
        dns_name_matches(host, "examples.com")) {
        *tags = isrg_root_x1_tags;
        return sizeof(isrg_root_x1_tags);
    }

    /* Google currently serves GTS Root R1 cross-signed by GlobalSign Root R1.
     * A single trust anchor substantially reduces parallel handshake memory. */
    if (dns_name_matches(host, "google.com") ||
        dns_name_matches(host, "google.co.jp") ||
        dns_name_matches(host, "gstatic.com") ||
        dns_name_matches(host, "googleapis.com") ||
        dns_name_matches(host, "googleusercontent.com")) {
        *tags = globalsign_root_r1_tags;
        return sizeof(globalsign_root_r1_tags);
    }

    *tags = trusted_ca_tags;
    return sizeof(trusted_ca_tags);
}

static bool header_value(const char *line, const char *end,
                         const char *value, bool parameters)
{
    const char *p = memchr(line, ':', end - line);
    if (!p) {
        return false;
    }
    p++;
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    size_t len = strlen(value);
    if ((size_t)(end - p) < len || strncasecmp(p, value, len) != 0) {
        return false;
    }
    p += len;
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    return p == end || (parameters && *p == ';');
}

static bool rewritable_content_type(const char *line, const char *end)
{
    return header_value(line, end, "text/html", true) ||
           header_value(line, end, "text/css", true) ||
           header_value(line, end, "text/javascript", true) ||
           header_value(line, end, "application/javascript", true) ||
           header_value(line, end, "application/x-javascript", true);
}

/* Modern sites can send several kilobytes of browser-policy and telemetry
 * metadata that IE 5 cannot use. Drop those fields while they are received so
 * the bounded 4 KiB response-header buffer remains useful for the status line
 * and representation framing fields. TLS validation is unaffected. */
static bool discard_legacy_irrelevant_header(const char *line,
                                             const char *colon)
{
    static const char *const names[] = {
        "Alt-Svc",
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "NEL",
        "Origin-Agent-Cluster",
        "Permissions-Policy",
        "Report-To",
        "Reporting-Endpoints",
        "Server-Timing",
        "Strict-Transport-Security",
    };
    size_t name_length = (size_t)(colon - line);

    for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
        size_t length = strlen(names[i]);

        if (name_length == length &&
            strncasecmp(line, names[i], length) == 0) {
            return true;
        }
    }

    return false;
}

enum html_mode {
    HTML_PASSTHROUGH,
    HTML_CHUNKED,
    HTML_LENGTH,
    HTML_CLOSE,
};

static bool parse_content_length(const char *line, const char *end, size_t *length)
{
    const char *p = strchr(line, ':') + 1;
    size_t value = 0;
    while (p < end && (*p == ' ' || *p == '\t')) { p++; }
    const char *start = p;
    while (p < end && *p >= '0' && *p <= '9') {
        unsigned int digit = (unsigned int)(*p++ - '0');
        if (value > (SIZE_MAX - digit) / 10) { return false; }
        value = value * 10 + digit;
    }
    if (p == start) { return false; }
    while (p < end && (*p == ' ' || *p == '\t')) { p++; }
    if (p != end) { return false; }
    *length = value;
    return true;
}

static enum html_mode transform_html_header(struct proxy_worker *worker,
                                            size_t *length)
{
    char *response_header = worker->response_header;
    bool rewritable = false, chunked = false, encoded = false;
    unsigned int transfer_fields = 0, length_fields = 0;
    bool valid_length = false;
    *length = 0;
    /* 204/304 have no response body; 206 must preserve range semantics. */
    if (strncmp(response_header + 9, "204", 3) == 0 ||
        strncmp(response_header + 9, "304", 3) == 0 ||
        strncmp(response_header + 9, "206", 3) == 0) {
        return HTML_PASSTHROUGH;
    }
    const char *line = strstr(response_header, "\r\n") + 2;
    while (*line != '\r') {
        const char *end = strstr(line, "\r\n");
        if (header_name(line, end, "Content-Type")) {
            rewritable = rewritable_content_type(line, end);
        }
        if (header_name(line, end, "Transfer-Encoding")) {
            transfer_fields++;
            chunked = header_value(line, end, "chunked", false);
        }
        if (header_name(line, end, "Content-Length")) {
            length_fields++;
            valid_length = parse_content_length(line, end, length);
        }
        if (header_name(line, end, "Content-Encoding") &&
            !header_value(line, end, "identity", false)) {
            encoded = true;
        }
        line = end + 2;
    }
    if (!rewritable || encoded) { return HTML_PASSTHROUGH; }
    if (transfer_fields != 0) {
        return chunked && transfer_fields == 1
             ? HTML_CHUNKED : HTML_PASSTHROUGH;
    }
    if (length_fields != 0) {
        return length_fields == 1 && valid_length
             ? HTML_LENGTH : HTML_PASSTHROUGH;
    }
    return HTML_CLOSE;
}

static void rewrite_location(struct proxy_worker *worker, size_t *len)
{
    char *response_header = worker->response_header;
    char *line = strstr(response_header, "\r\n") + 2;
    while (*line != '\r') {
        char *end = strstr(line, "\r\n");
        if (header_name(line, end, "Location")) {
            char *value = strchr(line, ':') + 1;
            while (value < end && (*value == ' ' || *value == '\t')) {
                value++;
            }
            if (end - value >= 8 && memcmp(value, "https://", 8) == 0) {
                memmove(value + 4, value + 5,
                        *len - (size_t)(value + 5 - response_header) + 1);
                (*len)--;
                end--;
                LOG_INF("Redirect rewrite: https:// -> http://");
            }
        }
        line = end + 2;
    }
}

static int send_streaming_html_header(struct proxy_worker *worker,
                                      int client_sock)
{
    char *response_header = worker->response_header;
    char *line = response_header;
    while (*line != '\r') {
        char *end = strstr(line, "\r\n");
        /* These metadata no longer describe the transformed representation. */
        if (!header_name(line, end, "Transfer-Encoding") &&
            !header_name(line, end, "Content-Length") &&
            !header_name(line, end, "Connection") &&
            !header_name(line, end, "Trailer") &&
            !header_name(line, end, "ETag") &&
            !header_name(line, end, "Content-MD5") &&
            !header_name(line, end, "Digest")) {
            int ret = send_all(client_sock, line, end + 2 - line);
            if (ret < 0) {
                return ret;
            }
        }
        line = end + 2;
    }
    return send_all(client_sock, "Connection: close\r\n\r\n",
                    sizeof("Connection: close\r\n\r\n") - 1);
}

static int write_to_client(void *context, const char *data, size_t length)
{
    int client_sock = *(int *)context;
    return send_all(client_sock, data, length);
}

static int write_to_rewriter(void *context, const char *data, size_t length)
{
    return html_rewriter_feed(context, data, length);
}

static int create_tls_socket(void)
{
    for (unsigned int attempt = 1;
         attempt <= TLS_SOCKET_CREATE_ATTEMPTS; attempt++) {
        k_mutex_lock(&tls_operation_lock, K_FOREVER);
        int sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
        int error = sock < 0 ? errno : 0;
        k_mutex_unlock(&tls_operation_lock);

        if (sock >= 0) {
            return sock;
        }

        if ((error != ENOENT && error != ENOMEM) ||
            attempt == TLS_SOCKET_CREATE_ATTEMPTS) {
            errno = error;
            return -1;
        }

        LOG_WRN("TLS socket resources busy; retry %u/%u",
                attempt, TLS_SOCKET_CREATE_ATTEMPTS - 1);
        k_msleep(TLS_SOCKET_RETRY_MS);
    }

    errno = ENOMEM;
    return -1;
}

static void close_tls_socket(int sock)
{
    k_mutex_lock(&tls_operation_lock, K_FOREVER);
    zsock_close(sock);
    k_mutex_unlock(&tls_operation_lock);
}

static int send_to_upstream(int sock, bool use_tls,
                            const char *data, size_t length)
{
    if (use_tls) {
        k_mutex_lock(&tls_operation_lock, K_FOREVER);
    }
    int ret = send_all(sock, data, length);
    if (use_tls) {
        k_mutex_unlock(&tls_operation_lock);
    }
    return ret;
}

static int upstream_to_client(struct proxy_worker *worker,
                              int client_sock,
                              enum proxy_request_method method,
                              const char *host,
                              const char *path,
                              const char *user_agent,
                              size_t content_length,
                              const char *initial_body,
                              size_t initial_body_length,
                              bool use_tls)
{
    struct zsock_addrinfo hints = {0};
    struct zsock_addrinfo *res = NULL;

    char rx[1024];

    bool response_started = false;
    int upstream_sock = -1;
    int ret;

    const char *method_name = method == PROXY_METHOD_HEAD ? "HEAD" :
                              method == PROXY_METHOD_POST ? "POST" : "GET";
    if (method == PROXY_METHOD_POST) {
        ret = snprintk(worker->https_request,
                       sizeof(worker->https_request),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: %s\r\n"
                       "Content-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "Accept-Encoding: identity\r\n"
                       "\r\n",
                       method_name, path, host,
                       user_agent[0] != '\0' ? user_agent :
                       "SecureLegacyGateway/0.1",
                       content_length);
    } else {
        ret = snprintk(worker->https_request,
                       sizeof(worker->https_request),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: %s\r\n"
                       "Connection: close\r\n"
                       "Accept-Encoding: identity\r\n"
                       "\r\n",
                       method_name, path, host,
                       user_agent[0] != '\0' ? user_agent :
                       "SecureLegacyGateway/0.1");
    }

    if (ret < 0 || ret >= sizeof(worker->https_request)) {
        LOG_ERR("Upstream request too large");
        return -1;
    }

    LOG_INF("Resolving %s", host);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = zsock_getaddrinfo(host, use_tls ? "443" : "80", &hints, &res);

    if (ret != 0 || res == NULL) {
        LOG_ERR("DNS failed for %s: %d", host, ret);
        return -1;
    }

    LOG_INF("DNS resolved");

    upstream_sock = use_tls ?
        create_tls_socket() :
        zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (upstream_sock < 0) {
        LOG_ERR("%s socket failed: %d", use_tls ? "TLS" : "HTTP", errno);
        zsock_freeaddrinfo(res);
        return -1;
    }

    if (use_tls) {
        k_mutex_lock(&tls_operation_lock, K_FOREVER);
    }
    ret = set_socket_timeout(upstream_sock, SO_RCVTIMEO,
                             UPSTREAM_IO_TIMEOUT_SEC, "upstream receive");
    if (use_tls) {
        k_mutex_unlock(&tls_operation_lock);
    }
    if (ret < 0) {
        goto error;
    }

    if (use_tls) {
        k_mutex_lock(&tls_operation_lock, K_FOREVER);
    }
    ret = set_socket_timeout(upstream_sock, SO_SNDTIMEO,
                             UPSTREAM_IO_TIMEOUT_SEC, "upstream send");
    if (use_tls) {
        k_mutex_unlock(&tls_operation_lock);
    }
    if (ret < 0) {
        goto error;
    }

    if (use_tls) {
        const sec_tag_t *ca_tags;
        size_t ca_tags_size = trusted_tags_for_host(host, &ca_tags);

        k_mutex_lock(&tls_operation_lock, K_FOREVER);
        ret = zsock_setsockopt(upstream_sock,
                               SOL_TLS,
                               TLS_SEC_TAG_LIST,
                               ca_tags,
                               ca_tags_size);
        k_mutex_unlock(&tls_operation_lock);

        if (ret < 0) {
            LOG_ERR("TLS_SEC_TAG_LIST failed: %d", errno);
            goto error;
        }

        k_mutex_lock(&tls_operation_lock, K_FOREVER);
        ret = zsock_setsockopt(upstream_sock,
                               SOL_TLS,
                               TLS_HOSTNAME,
                               host,
                               strlen(host) + 1);
        k_mutex_unlock(&tls_operation_lock);

        if (ret < 0) {
            LOG_ERR("TLS_HOSTNAME failed: %d", errno);
            goto error;
        }
    }

    LOG_INF("Connecting %s to %s%s", use_tls ? "HTTPS" : "HTTP",
            host, path);

    uint32_t connect_started_ms = k_uptime_get_32();
    if (use_tls) {
        k_mutex_lock(&tls_operation_lock, K_FOREVER);
    }
    ret = zsock_connect(upstream_sock,
                        res->ai_addr,
                        res->ai_addrlen);
    int connect_error = ret < 0 ? errno : 0;
    if (use_tls) {
        k_mutex_unlock(&tls_operation_lock);
    }

    if (ret < 0) {
        if (connect_error == ENOMEM) {
            LOG_ERR("%s connect failed: mbed TLS heap exhausted",
                    use_tls ? "TLS" : "HTTP");
        } else {
            LOG_ERR("%s connect failed: %d",
                    use_tls ? "TLS" : "HTTP", connect_error);
        }
        goto error;
    }

    uint32_t connect_elapsed_ms = k_uptime_get_32() - connect_started_ms;
    LOG_INF("%s connected in %u ms",
            use_tls ? "TLS" : "HTTP upstream", connect_elapsed_ms);

    ret = send_to_upstream(upstream_sock, use_tls,
                           worker->https_request,
                           strlen(worker->https_request));

    if (ret < 0) {
        LOG_ERR("Upstream send failed");
        goto error;
    }

    if (method == PROXY_METHOD_POST) {
        if (initial_body_length > content_length) {
            LOG_ERR("POST body exceeds declared Content-Length");
            ret = -EINVAL;
            goto error;
        }
        if (initial_body_length > 0) {
            ret = send_to_upstream(upstream_sock, use_tls,
                                   initial_body, initial_body_length);
            if (ret < 0) {
                LOG_ERR("Upstream POST body send failed");
                goto error;
            }
        }

        size_t body_remaining = content_length - initial_body_length;
        while (body_remaining > 0) {
            size_t wanted = body_remaining < sizeof(rx) ?
                            body_remaining : sizeof(rx);
            ret = zsock_recv(client_sock, rx, wanted, 0);
            if (ret < 0) {
                ret = -errno;
                LOG_ERR("POST body receive failed: %d", -ret);
                goto error;
            }
            if (ret == 0) {
                LOG_ERR("POST body ended before Content-Length");
                ret = -ECONNRESET;
                goto error;
            }
            int send_ret = send_to_upstream(upstream_sock, use_tls,
                                            rx, (size_t)ret);
            if (send_ret < 0) {
                ret = send_ret;
                LOG_ERR("Upstream POST body send failed");
                goto error;
            }
            body_remaining -= (size_t)ret;
        }
        LOG_INF("Upstream POST sent: %zu body bytes", content_length);
    } else {
        LOG_INF("Upstream %s sent", method_name);
    }
    LOG_INF("Relaying response to HTTP client");

    size_t header_len = 0;
    size_t header_line_start = 0;
    bool header_done = false;
    bool response_status_line = true;
    bool dropping_header_line = false;
    bool dropped_line_saw_cr = false;
    unsigned int discarded_header_fields = 0;
    size_t content_remaining = 0;
    enum html_mode mode = HTML_PASSTHROUGH;
    struct html_rewriter rewriter;
    struct chunk_decoder chunk_decoder;

    while (1) {
        if (use_tls) {
            k_mutex_lock(&tls_operation_lock, K_FOREVER);
        }
        ret = zsock_recv(upstream_sock, rx, sizeof(rx), 0);
        if (use_tls) {
            k_mutex_unlock(&tls_operation_lock);
        }
        if (ret < 0) {
            LOG_ERR("Upstream recv failed: %d", errno);
            goto error;
        }
        if (ret == 0) {
            if (!header_done) {
                LOG_ERR("Incomplete upstream response");
                goto error;
            }
            if (mode == HTML_CLOSE) {
                ret = html_rewriter_finish(&rewriter);
                if (ret < 0) {
                    goto error;
                }
                LOG_INF("Streaming text rewrite: %zu URLs",
                        rewriter.replacements);
            } else if (mode == HTML_LENGTH || mode == HTML_CHUNKED) {
                LOG_ERR("Incomplete upstream response body");
                goto error;
            }
            break;
        }
        size_t offset = 0, received = (size_t)ret;
        if (!header_done) {
            while (offset < received) {
                char byte = rx[offset++];

                if (dropping_header_line) {
                    if (dropped_line_saw_cr && byte == '\n') {
                        dropping_header_line = false;
                        dropped_line_saw_cr = false;
                        header_line_start = header_len;
                    } else {
                        dropped_line_saw_cr = byte == '\r';
                    }
                    continue;
                }

                if (header_len >= sizeof(worker->response_header) - 1) {
                    LOG_ERR("HTTP response header too large");
                    goto error;
                }
                worker->response_header[header_len++] = byte;
                worker->response_header[header_len] = 0;

                if (!response_status_line && byte == ':' &&
                    discard_legacy_irrelevant_header(
                        worker->response_header + header_line_start,
                        worker->response_header + header_len - 1)) {
                    header_len = header_line_start;
                    worker->response_header[header_len] = 0;
                    dropping_header_line = true;
                    dropped_line_saw_cr = false;
                    discarded_header_fields++;
                    continue;
                }

                if (header_len >= 2 &&
                    memcmp(worker->response_header + header_len - 2,
                           "\r\n", 2) == 0 &&
                    header_len - header_line_start > 2) {
                    response_status_line = false;
                    header_line_start = header_len;
                }

                if (header_len >= 4 &&
                    memcmp(worker->response_header + header_len - 4,
                           "\r\n\r\n", 4) == 0) {
                    /* Consume informational responses before the final header. */
                    if (header_len >= 12 && worker->response_header[9] == '1') {
                        header_len = 0;
                        header_line_start = 0;
                        response_status_line = true;
                        discarded_header_fields = 0;
                        continue;
                    }
                    if (discarded_header_fields > 0) {
                        LOG_INF("Removed %u legacy-irrelevant response headers",
                                discarded_header_fields);
                    }
                    rewrite_location(worker, &header_len);
                    mode = transform_html_header(worker, &content_remaining);
                    if (method == PROXY_METHOD_HEAD) {
                        mode = HTML_PASSTHROUGH;
                    }
                    header_done = true;
                    response_started = true;
                    if (mode == HTML_PASSTHROUGH) {
                        ret = send_all(client_sock, worker->response_header,
                                       header_len);
                        if (ret < 0) {
                            goto error;
                        }
                    } else {
                        ret = send_streaming_html_header(worker, client_sock);
                        if (ret < 0) {
                            goto error;
                        }
                        html_rewriter_init(&rewriter, write_to_client,
                                           &client_sock);
                        if (mode == HTML_CHUNKED) {
                            chunk_decoder_init(&chunk_decoder,
                                               write_to_rewriter, &rewriter);
                        }
                    }
                    break;
                }
            }
            if (!header_done) {
                continue;
            }
            if (method == PROXY_METHOD_HEAD) {
                break;
            }
        }
        size_t available = received - offset;
        if (mode == HTML_LENGTH) {
            if (available > content_remaining) {
                LOG_ERR("Upstream body exceeds Content-Length");
                goto error;
            }
            ret = html_rewriter_feed(&rewriter, rx + offset, available);
            if (ret < 0) {
                goto error;
            }
            content_remaining -= available;
            if (content_remaining == 0) {
                ret = html_rewriter_finish(&rewriter);
                if (ret < 0) {
                    goto error;
                }
                LOG_INF("Streaming fixed-length text rewrite: %zu URLs",
                        rewriter.replacements);
                break;
            }
            continue;
        }
        if (mode == HTML_CHUNKED) {
            ret = chunk_decoder_feed(&chunk_decoder, rx + offset, available);
            if (ret < 0) {
                if (!peer_closed_result(ret) &&
                    !client_write_timeout_result(ret)) {
                    LOG_ERR("Malformed chunked HTML: %d", ret);
                }
                goto error;
            }
            if (chunk_decoder_complete(&chunk_decoder)) {
                ret = html_rewriter_finish(&rewriter);
                if (ret < 0) {
                    goto error;
                }
                LOG_INF("Streaming chunked text rewrite: %zu URLs",
                        rewriter.replacements);
                break;
            }
            continue;
        }
        if (mode == HTML_CLOSE) {
            ret = html_rewriter_feed(&rewriter, rx + offset, available);
            if (ret < 0) {
                goto error;
            }
            continue;
        }
        ret = send_all(client_sock, rx + offset, available);
        if (ret < 0) {
            goto error;
        }
    }

    LOG_INF("Relay complete");
    if (use_tls) {
        close_tls_socket(upstream_sock);
    } else {
        zsock_close(upstream_sock);
    }
    zsock_freeaddrinfo(res);

    return 0;

error:
    if (upstream_sock >= 0) {
        if (use_tls) {
            close_tls_socket(upstream_sock);
        } else {
            zsock_close(upstream_sock);
        }
    }

    if (res != NULL) {
        zsock_freeaddrinfo(res);
    }

    if (response_started && peer_closed_result(ret)) {
        return -ECANCELED;
    }
    if (response_started && client_write_timeout_result(ret)) {
        return -ETIMEDOUT;
    }

    return response_started ? -EALREADY : -1;
}

static int receive_request_header(struct proxy_worker *worker,
                                  int client_sock,
                                  size_t *request_length)
{
    int ret = set_socket_timeout(client_sock, SO_RCVTIMEO,
                                 CLIENT_REQUEST_TIMEOUT_SEC,
                                 "client receive");
    if (ret < 0) {
        return ret;
    }

    *request_length = 0;
    while (*request_length < PROXY_REQUEST_HEADER_SIZE) {
        ret = zsock_recv(client_sock,
                         worker->request_header + *request_length,
                         PROXY_REQUEST_HEADER_SIZE - *request_length,
                         0);
        if (ret < 0) {
            return -errno;
        }
        if (ret == 0) {
            return -ECONNRESET;
        }

        *request_length += (size_t)ret;
        worker->request_header[*request_length] = '\0';
        if (proxy_request_header_complete(worker->request_header,
                                          *request_length)) {
            return 0;
        }
    }

    return -EMSGSIZE;
}

static void send_client_error(int client_sock,
                              const char *status,
                              const char *body,
                              const char *extra_header)
{
    char header[192];
    int length = snprintk(header, sizeof(header),
                          "HTTP/1.1 %s\r\n"
                          "Content-Length: %zu\r\n"
                          "%s"
                          "Connection: close\r\n"
                          "\r\n",
                          status, strlen(body), extra_header);
    if (length < 0 || length >= sizeof(header)) {
        return;
    }

    if (send_all(client_sock, header, (size_t)length) == 0) {
        send_all(client_sock, body, strlen(body));
    }
}

static void handle_client(struct proxy_worker *worker, int client_sock)
{
    int ret;

    LOG_INF("HTTP client connected (worker %u)", worker->id);

    ret = set_socket_timeout(client_sock, SO_SNDTIMEO,
                             CLIENT_SEND_TIMEOUT_SEC, "client send");
    if (ret < 0) {
        goto close_client;
    }

    size_t request_length = 0;
    ret = receive_request_header(worker, client_sock, &request_length);
    if (ret < 0) {
        if (ret == -EMSGSIZE) {
            LOG_WRN("HTTP request header too large");
            send_client_error(client_sock,
                              "431 Request Header Fields Too Large",
                              "Request Header Fields Too Large", "");
        } else if (ret == -EAGAIN || ret == -ETIMEDOUT) {
            LOG_WRN("HTTP request receive timeout");
            send_client_error(client_sock, "408 Request Timeout",
                              "Request Timeout", "");
        } else {
            LOG_WRN("HTTP request receive failed: %d", ret);
        }
        goto close_client;
    }

    enum proxy_request_result parse_result =
        proxy_request_parse(worker->request_header, request_length,
                            &worker->parsed_request);
    if (parse_result != PROXY_REQUEST_OK) {
        if (parse_result == PROXY_REQUEST_METHOD_NOT_ALLOWED) {
            const char *method_end =
                memchr(worker->request_header, ' ', request_length);
            size_t method_length = method_end != NULL ?
                (size_t)(method_end - worker->request_header) : 0;
            if (method_length > 0 && method_length <= 16) {
                LOG_WRN("Unsupported HTTP method: %.*s",
                        (int)method_length, worker->request_header);
            } else {
                LOG_WRN("Unsupported HTTP method");
            }
            send_client_error(client_sock, "405 Method Not Allowed",
                              "Method Not Allowed",
                              "Allow: GET, HEAD, POST\r\n");
        } else if (parse_result == PROXY_REQUEST_URI_TOO_LONG) {
            LOG_WRN("Proxy request URI too long");
            send_client_error(client_sock, "414 URI Too Long",
                              "URI Too Long", "");
        } else if (parse_result == PROXY_REQUEST_LENGTH_REQUIRED) {
            LOG_WRN("POST request requires Content-Length");
            send_client_error(client_sock, "411 Length Required",
                              "Length Required", "");
        } else if (parse_result == PROXY_REQUEST_PAYLOAD_TOO_LARGE) {
            LOG_WRN("POST body exceeds %d bytes",
                    PROXY_POST_MAX_BODY_SIZE);
            send_client_error(client_sock, "413 Payload Too Large",
                              "Payload Too Large", "");
        } else if (parse_result == PROXY_REQUEST_UNSUPPORTED_MEDIA_TYPE) {
            LOG_WRN("Unsupported POST Content-Type");
            send_client_error(client_sock, "415 Unsupported Media Type",
                              "Unsupported Media Type", "");
        } else if (parse_result ==
                   PROXY_REQUEST_UNSUPPORTED_TRANSFER_ENCODING) {
            LOG_WRN("Chunked request body is not supported");
            send_client_error(client_sock, "501 Not Implemented",
                              "Chunked request body is not supported", "");
        } else {
            LOG_WRN("Invalid proxy request: %d", parse_result);
            send_client_error(client_sock, "400 Bad Request",
                              "Bad Request", "");
        }
        goto close_client;
    }

    const char *method_name =
        worker->parsed_request.method == PROXY_METHOD_HEAD ? "HEAD" :
        worker->parsed_request.method == PROXY_METHOD_POST ? "POST" : "GET";
    LOG_INF("Parsed Method: %s", method_name);
    LOG_INF("Parsed Host: %s", worker->parsed_request.host);
    LOG_INF("Parsed Path: %s", worker->parsed_request.path);
    LOG_INF("Client User-Agent: %s",
            worker->parsed_request.user_agent[0] != '\0' ?
            worker->parsed_request.user_agent : "(not supplied)");

    size_t initial_body_length =
        request_length - worker->parsed_request.header_length;
    if (worker->parsed_request.method == PROXY_METHOD_POST &&
        initial_body_length > worker->parsed_request.content_length) {
        LOG_WRN("POST body exceeds declared Content-Length");
        send_client_error(client_sock, "400 Bad Request",
                          "Bad Request", "");
        goto close_client;
    }

    uint32_t transaction_started_ms = k_uptime_get_32();
    ret = upstream_to_client(worker, client_sock,
                             worker->parsed_request.method,
                             worker->parsed_request.host,
                             worker->parsed_request.path,
                             worker->parsed_request.user_agent,
                             worker->parsed_request.content_length,
                             worker->request_header +
                             worker->parsed_request.header_length,
                             worker->parsed_request.method ==
                             PROXY_METHOD_POST ? initial_body_length : 0,
                             true);
    uint32_t transaction_elapsed_ms =
        k_uptime_get_32() - transaction_started_ms;
    if (ret == 0) {
        LOG_INF("Gateway transaction SUCCESS in %u ms",
                transaction_elapsed_ms);
    } else if (ret == -ECANCELED) {
        LOG_INF("Gateway transaction cancelled by HTTP client after %u ms",
                transaction_elapsed_ms);
    } else if (ret == -ETIMEDOUT) {
        LOG_WRN("Gateway response paused too long by HTTP client after %u ms",
                transaction_elapsed_ms);
    } else {
        static const char bad_gateway[] =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Length: 11\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Gateway";

        if (ret != -EALREADY) {
            send_all(client_sock, bad_gateway, strlen(bad_gateway));
        }
        LOG_ERR("Gateway transaction FAILED after %u ms",
                transaction_elapsed_ms);
    }

close_client:
    zsock_close(client_sock);
    LOG_INF("HTTP client closed (worker %u)", worker->id);
}

static void proxy_worker_entry(void *arg1, void *arg2, void *arg3)
{
    struct proxy_worker *worker = arg1;

    ARG_UNUSED(arg2);
    ARG_UNUSED(arg3);

    while (1) {
        int client_sock;

        k_msgq_get(&client_queue, &client_sock, K_FOREVER);
        handle_client(worker, client_sock);
    }
}

int main(void)
{
    struct sockaddr_in addr = {0};

    int server_sock;
    int ret;

    net_mgmt_init_event_callback(&dhcp_event_callback,
                                 dhcp_bound_handler,
                                 NET_EVENT_IPV4_DHCP_BOUND);
    net_mgmt_add_event_callback(&dhcp_event_callback);

    LOG_INF("MCX Dynamic HTTP-to-HTTPS Gateway starting");
    LOG_INF("IPv4 mode: DHCP only (address, gateway and DNS from router)");
    LOG_INF("HTTP proxy port: %d", LOCAL_PORT);

#if defined(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)
    if (els_psa_selftest() != 0) {
        LOG_ERR("ELS PSA self-test failed; proxy startup stopped");
        return 0;
    }
#endif

    k_sleep(K_SECONDS(3));

    log_ipv4_config(net_if_get_default(), "Active");

    ret = install_trusted_cas();
    if (ret < 0) {
        return 0;
    }

    for (unsigned int i = 0; i < PROXY_WORKER_COUNT; i++) {
        proxy_workers[i].id = i + 1;
        k_thread_create(&proxy_worker_threads[i], proxy_worker_stacks[i],
                        K_THREAD_STACK_SIZEOF(proxy_worker_stacks[i]),
                        proxy_worker_entry, &proxy_workers[i], NULL, NULL,
                        5, 0, K_NO_WAIT);
    }

    server_sock = zsock_socket(AF_INET,
                               SOCK_STREAM,
                               IPPROTO_TCP);

    if (server_sock < 0) {
        LOG_ERR("Server socket failed: %d", errno);
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOCAL_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = zsock_bind(server_sock,
                     (struct sockaddr *)&addr,
                     sizeof(addr));

    if (ret < 0) {
        LOG_ERR("bind failed: %d", errno);
        return 0;
    }

    ret = zsock_listen(server_sock, CLIENT_QUEUE_DEPTH);

    if (ret < 0) {
        LOG_ERR("listen failed: %d", errno);
        return 0;
    }

    LOG_INF("Dynamic Gateway ready (%d concurrent clients)",
            PROXY_WORKER_COUNT);

    while (1) {
        int client_sock = zsock_accept(server_sock, NULL, NULL);

        if (client_sock < 0) {
            LOG_ERR("accept failed: %d", errno);
            continue;
        }

        /* Never stop accepting while the work queue is full. An accepted
         * socket can otherwise retain RX packets indefinitely and starve the
         * ENET DMA ring during a burst of parallel browser connections. */
        ret = k_msgq_put(&client_queue, &client_sock, K_NO_WAIT);
        if (ret < 0) {
            LOG_WRN("HTTP client queue full; closing excess connection");
            zsock_close(client_sock);
        }
    }

    return 0;
}
