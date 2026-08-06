/* WiFi Scan page fragments.
 *
 * Chrome (head, nav, footer) comes from page_common.h via send_page_head() and
 * send_page_foot(); only the page body lives here. No <style> block and no
 * printf conversions, so these stream straight through SEND_CHUNK.
 */
#include "router_config.h"

#if !CONFIG_ETH_UPLINK

/* class=r: below 640px the rows reflow into one compact block per network so
 * nothing needs scrolling sideways on a phone. */
#define SCAN_TABLE_OPEN "<div class=c><div class=tw><table class=\"t r\"><thead><tr>" \
    "<th>Network</th><th>Signal</th><th>Channel</th><th>Security</th>"

#define SCAN_TABLE_ACTION_TH "<th></th>"

#define SCAN_TABLE_MID "</tr></thead><tbody>"

#define SCAN_TABLE_CLOSE "</tbody></table></div></div>"

#endif /* !CONFIG_ETH_UPLINK */
