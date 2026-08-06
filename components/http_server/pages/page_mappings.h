/* Mappings page fragments: connected clients, DHCP reservations, port
 * forwarding.
 *
 * Chrome comes from page_common.h through send_page_head() / send_page_foot().
 *
 * The "Select" button that copies a client into the reservation form used to
 * land inside onclick="fillDhcpForm('...')" — an HTML attribute wrapping a
 * JavaScript string literal, two layers of escaping deep, which is why the
 * device name had to be squeezed through a whitelist filter first. It carries
 * plain data-* attributes now: one layer of escaping, no filter, and the real
 * name survives.
 */
#include "router_config.h"

/* Substitutes: escaped message. */
#define MAPPINGS_ERROR "<p class=\"al er\">%s</p>"

#define MAPPINGS_CLIENTS_OPEN "<div class=c><h2>Connected clients</h2>" \
    "<div class=tw><table class=\"t r\"><thead><tr>" \
    "<th>MAC address</th><th>IP</th><th>Name</th>"

/* Only present when per-client accounting is compiled in and switched on. */
#define MAPPINGS_CLIENTS_TRAFFIC "<th>Traffic</th>"

#define MAPPINGS_CLIENTS_HEAD_END "<th></th></tr></thead><tbody>"

/* Substitutes: column count. */
#define MAPPINGS_CLIENTS_EMPTY "<tr><td colspan=%d class=n>No clients connected.</td></tr>"

#define MAPPINGS_TABLE_CLOSE "</tbody></table></div>"
#define MAPPINGS_CARD_CLOSE "</div>"

/* Substitutes: pool start, pool end. */
#define MAPPINGS_DHCP_OPEN "<div class=c><h2>DHCP reservations</h2>" \
    "<p class=n>Pool: %s &ndash; %s</p>" \
    "<div class=tw><table class=\"t r\"><thead><tr>" \
    "<th>MAC address</th><th>IP</th><th>Name</th><th></th>" \
    "</tr></thead><tbody>"

#define MAPPINGS_DHCP_EMPTY "<tr><td colspan=4 class=n>No reservations.</td></tr>"

/* The ids are what app.js writes into when a client's Reserve button is used.
 *
 * "Block" needs no IP: the handler ignores the address field entirely for that
 * action, which is why the button no longer carries an onclick that zeroes it
 * first. */
#define MAPPINGS_DHCP_FORM "<form action=/mappings method=GET>" \
    "<div class=c><h2>Add a reservation</h2><div class=f>" \
    "<label for=rmac>MAC address</label>" \
    "<input id=rmac type=text name=dhcp_mac placeholder='AA:BB:CC:DD:EE:FF'>" \
    "<label for=rip>IP</label>" \
    "<input id=rip type=text name=dhcp_ip placeholder='192.168.4.100'>" \
    "<label for=rname>Name</label>" \
    "<input id=rname type=text name=dhcp_name placeholder='optional'>" \
    "<div class=act>" \
    "<button class=\"b p\" type=submit name=dhcp_action value='Add Reservation'>" \
    "Add reservation</button> " \
    "<button class=\"b d\" type=submit name=dhcp_action value='Block' " \
    "data-c='Block this MAC address from getting a lease?'>Block MAC</button>" \
    "</div></div></div></form>"

#define MAPPINGS_PORTFWD_OPEN "<div class=c><h2>Port forwarding</h2>" \
    "<div class=tw><table class=\"t r\"><thead><tr>" \
    "<th>Listening on</th><th>Forwards to</th><th>Uplink</th><th></th>" \
    "</tr></thead><tbody>"

#define MAPPINGS_PORTFWD_EMPTY "<tr><td colspan=4 class=n>No forwards.</td></tr>"

#define MAPPINGS_PORTFWD_OFF "<div class=c><h2>Port forwarding</h2>" \
    "<p class=n>Not available in routed mode; it needs NAT.</p></div>"

#if CONFIG_ETH_UPLINK
#define PORTMAP_IFACE_OPTIONS "<option value=STA>Ethernet</option>" \
    "<option value=VPN>VPN</option>"
#define PORTMAP_IFACE_WAN "ETH"
#else
#define PORTMAP_IFACE_OPTIONS "<option value=STA>WiFi</option>" \
    "<option value=VPN>VPN</option>"
#define PORTMAP_IFACE_WAN "STA"
#endif

#define MAPPINGS_PORTFWD_FORM "<form action=/mappings method=GET>" \
    "<div class=c><h2>Add a forward</h2><div class=f>" \
    "<label for=pi>Uplink</label>" \
    "<select id=pi name=iface>" PORTMAP_IFACE_OPTIONS "</select>" \
    "<label for=pp>Protocol</label>" \
    "<select id=pp name=proto><option value=TCP>TCP</option>" \
    "<option value=UDP>UDP</option></select>" \
    "<label for=pe>External port</label>" \
    "<input id=pe type=number name=ext_port min=1 max=65535 placeholder='8080'>" \
    "<label for=pd>Internal address</label>" \
    "<input id=pd type=text name=int_ip placeholder='IP or device name'>" \
    "<label for=pt>Internal port</label>" \
    "<input id=pt type=number name=int_port min=1 max=65535 placeholder='80'>" \
    "<button class=\"b p act\" type=submit name=port_action value='Add Forward'" \
    ">Add forward</button>" \
    "</div></div></form>"
