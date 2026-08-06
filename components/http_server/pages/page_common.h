/* Chrome shared by every page: document head, tab bar, footer.
 *
 * These are plain string literals with no printf conversions in them, so they
 * go straight to SEND_CHUNK. Only fragments that actually substitute values
 * need snprintf — which is what keeps the doubled %% escapes out of the
 * templates now that the inline <style> blocks are gone.
 */

#ifndef PAGE_COMMON_H
#define PAGE_COMMON_H

/* Streamed as: DOC_HEAD_A  <title text>  DOC_HEAD_B */
#define DOC_HEAD_A "<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>" \
    "<meta name=viewport content='width=device-width,initial-scale=1'>" \
    "<link rel=stylesheet href=/app.css><link rel=icon href=/favicon.svg>" \
    "<title>"

#define DOC_HEAD_B "</title></head><body><div class=w>"

/* Page header: logo, title, optional right-hand slot (logout). */
#define HDR_A "<header class=hd><img src=/favicon.svg alt=\"\"><h1>"
#define HDR_B "</h1>"
#define HDR_C "</header>"

#define LOGOUT_FORM "<form method=post action=/ style=margin:0>" \
    "<button class=\"b s\" name=logout value=1>Log out</button></form>"

#define NAV_OPEN "<nav class=nav>"
#define NAV_CLOSE "</nav>"

#define DOC_FOOT_A "<footer class=ft>"
#define DOC_FOOT_B "</footer></div><script src=/app.js defer></script></body></html>"

/* Which tab is highlighted. Order matches the NAV[] table in http_server.c. */
typedef enum {
    TAB_NONE = -1,
    TAB_HOME = 0,
    TAB_SETUP,
    TAB_SCAN,
    TAB_CONFIG,
    TAB_MAPPINGS,
    TAB_FIREWALL,
    TAB_VPN,
} page_tab_t;

#endif /* PAGE_COMMON_H */
