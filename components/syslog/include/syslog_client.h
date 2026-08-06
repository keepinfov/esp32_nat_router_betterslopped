/* Syslog client - forward ESP logs to a remote syslog server via UDP
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYSLOG_DEFAULT_PORT     514
#define SYSLOG_MAX_SERVER_LEN   64

/**
 * Initialize syslog client. Loads config from NVS and installs
 * the vprintf hook if syslog was previously enabled.
 * Call after NVS init and network init.
 */
#ifdef CONFIG_SYSLOG_CLIENT

esp_err_t syslog_init(void);

/**
 * Enable syslog forwarding to the given server.
 * Saves config to NVS and opens the UDP socket.
 */
esp_err_t syslog_enable(const char *server, uint16_t port);

/**
 * Disable syslog forwarding. Saves config to NVS and closes socket.
 */
esp_err_t syslog_disable(void);

/**
 * Check if syslog forwarding is currently enabled.
 */
bool syslog_is_enabled(void);

/**
 * Get current syslog configuration.
 */
void syslog_get_config(bool *enabled, char *server, size_t server_len, uint16_t *port);

/**
 * Notify syslog that network connectivity is available.
 * Call from the WiFi GOT_IP event handler. Re-resolves DNS
 * and opens the UDP socket if syslog is enabled.
 */
void syslog_notify_connected(void);

#else /* !CONFIG_SYSLOG_CLIENT */

/* Switched off: do-nothing inlines, so no caller needs an #ifdef.  Each getter
 * reports what a subsystem that is present but idle would report, which every
 * caller already handles. */

static inline esp_err_t syslog_init(void) { return ESP_OK; }
static inline esp_err_t syslog_enable(const char *server, uint16_t port)
{
    (void)server; (void)port;
    return ESP_ERR_NOT_SUPPORTED;
}
static inline esp_err_t syslog_disable(void) { return ESP_OK; }
static inline bool syslog_is_enabled(void) { return false; }
static inline void syslog_get_config(bool *enabled, char *server,
                                     size_t server_len, uint16_t *port)
{
    if (enabled) *enabled = false;
    if (server && server_len) server[0] = '\0';
    if (port) *port = 0;
}
static inline void syslog_notify_connected(void) {}

#endif /* CONFIG_SYSLOG_CLIENT */

#ifdef __cplusplus
}
#endif
