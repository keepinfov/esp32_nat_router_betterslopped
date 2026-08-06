/* Getting Started page fragments.
 *
 * Chrome comes from page_common.h via send_page_head() / send_page_foot().
 * The reboot notice used to be an inline script that blanked the body and
 * waited a fixed ten seconds; the handler knows whether it started a restart,
 * so it says so directly and the page needs no JavaScript at all.
 */
#include "router_config.h"

#if !CONFIG_ETH_UPLINK

#define SETUP_REBOOT_NOTE "<p class=\"al ok\">Settings saved. The router is " \
    "restarting — reconnect to the new network, then reload this page.</p>"

#define SETUP_INTRO "<p class=\"al\">Name the network this router hands out, " \
    "then tell it which WiFi to get its own internet from.</p>"

/* Substitutes: escaped AP SSID, escaped uplink SSID. */
#define SETUP_CHUNK_FORM "<form action=/setup method=POST>" \
    "<div class=c><h2>Access point</h2><div class=f>" \
    "<label for=apn>Network name</label>" \
    "<input id=apn type=text name=ap_ssid value='%s' placeholder='Hotspot name'>" \
    "<label for=app>Password</label>" \
    "<input id=app type=password name=ap_password placeholder='unchanged'>" \
    "</div></div>" \
    "<div class=c><h2>Uplink</h2><div class=f>" \
    "<label for=upn>WiFi network</label>" \
    "<input id=upn type=text name=ssid value='%s' placeholder='Network to join'>" \
    "<label for=upp>Password</label>" \
    "<input id=upp type=password name=password placeholder='unchanged'>" \
    "<p class=hint>Pick one from <a href=/scan>Scan</a> to fill this in.</p>" \
    "<button class=\"b p act\" type=submit>Save and restart</button>" \
    "</div></div></form>"

#endif /* !CONFIG_ETH_UPLINK */
