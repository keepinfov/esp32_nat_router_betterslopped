#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CONFIG_OLED_DISPLAY already depends on the two targets that can have a
 * display wired up, so it subsumes the target test this used to make — and it
 * also lets a build on one of those targets leave the driver out. */
#ifdef CONFIG_OLED_DISPLAY

#if defined(CONFIG_IDF_TARGET_ESP32S3)
#define OLED_DEFAULT_SDA  17
#define OLED_DEFAULT_SCL  18
#else
#define OLED_DEFAULT_SDA  5
#define OLED_DEFAULT_SCL  6
#endif
#define OLED_I2C_ADDR     0x3C

/**
 * @brief Initialize OLED display from NVS config.
 * If enabled, starts the display update task.
 */
void oled_display_init(void);

/**
 * @brief Enable OLED display (persisted to NVS, requires reboot).
 */
void oled_display_enable(void);

/**
 * @brief Disable OLED display (persisted to NVS, requires reboot).
 */
void oled_display_disable(void);

/**
 * @brief Set I2C GPIO pins (persisted to NVS, requires reboot).
 */
void oled_display_set_gpio(int sda, int scl);

/**
 * @brief Get current OLED config.
 * @param[out] enabled  Whether OLED is enabled
 * @param[out] sda      SDA GPIO pin
 * @param[out] scl      SCL GPIO pin
 */
void oled_display_get_config(bool *enabled, int *sda, int *scl);

#else /* !CONFIG_OLED_DISPLAY */

static inline void oled_display_init(void) {}
static inline void oled_display_enable(void) {}
static inline void oled_display_disable(void) {}
static inline void oled_display_set_gpio(int sda, int scl) { (void)sda; (void)scl; }
static inline void oled_display_get_config(bool *enabled, int *sda, int *scl) {
    if (enabled) *enabled = false;
    if (sda) *sda = 0;
    if (scl) *scl = 0;
}

#endif /* CONFIG_OLED_DISPLAY */

#ifdef __cplusplus
}
#endif
