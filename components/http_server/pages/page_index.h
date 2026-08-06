/* Status page fragments.
 *
 * Document head, tab bar and footer come from page_common.h through
 * send_page_head() / send_page_foot(); the navigation buttons that used to sit
 * in the middle of this page are the tab bar now. What is left is the status
 * card itself.
 */
#include "router_config.h"

#if CONFIG_ETH_UPLINK
#define INDEX_TITLE "ESP32 NAT Router (LAN)"
#else
#define INDEX_TITLE "ESP32 NAT Router"
#endif

/* class=kv: a key/value readout, so it keeps its two columns on a phone
 * instead of reflowing the way record lists do. */
#define INDEX_CHUNK_STATUS_OPEN "<div class=c><h2>System status</h2><table class=\"t kv\"><tbody>"

#define INDEX_CHUNK_STATUS_CLOSE "</tbody></table></div>"
