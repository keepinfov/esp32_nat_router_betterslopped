/* Configuration page fragments.
 *
 * Chrome comes from page_common.h through send_page_head() / send_page_foot().
 *
 * Eight settings groups used to be eight stacked <h2> blocks, so reaching the
 * danger zone meant scrolling past everything else. They are <details> in one
 * card now, with the access point open: the whole page is one screen until you
 * open the group you came for.
 *
 * Three things this page used to carry in flash are gone. The inline
 * stylesheet is /app.css. The "Settings saved! Rebooting..." banner was a
 * script that read window.location.search and replaced document.body — the
 * handler knows whether it queued a restart, so it says so itself. And the
 * ~4 KB of OTA / backup / restore JavaScript is in /app.js, where it is
 * minified and gzipped instead of embedded verbatim as a C string.
 */
#include "router_config.h"
#include "wifi_config.h"

#define CONFIG_REBOOT_NOTE "<p class=\"al ok\">Saved. The router is " \
    "restarting; reconnect and reload this page.</p>"

/* What the uplink is called wherever a build has to name it. */
#if CONFIG_ETH_UPLINK
#define RC_UPLINK_LABEL "Ethernet"
#else
#define RC_UPLINK_LABEL "WiFi"
#endif

#define CONFIG_OPEN "<div class=c>"
#define CONFIG_CLOSE "</div>"

/* Access point ------------------------------------------------------------
 *
 * Substitutes: ssid, address, hostname, DNS, MAC, [channel,] three auth
 * selections, then the NAT / enabled / open / hidden checkbox states.
 */
#if CONFIG_ETH_UPLINK
#define CONFIG_AP_CHANNEL "<label for=apc>Channel</label>" \
    "<input id=apc type=number name=ap_channel min=0 max=13 value='%d'>" \
    "<p class=hint>0 picks a channel automatically.</p>"
#else
#define CONFIG_AP_CHANNEL ""
#endif

#define CONFIG_AP "<details open><summary>Access point</summary>" \
    "<form action=/config method=GET><div class=f>" \
    "<label for=aps>Network name</label>" \
    "<input id=aps type=text name=ap_ssid value='%s' placeholder='Hotspot name'>" \
    "<label for=apw>Password</label>" \
    "<input id=apw type=password name=ap_password placeholder='unchanged'>" \
    "<label for=api>Router address</label>" \
    "<input id=api type=text name=ap_ip_addr value='%s' placeholder='192.168.4.1'>" \
    "<label for=aph>Hostname</label>" \
    "<input id=aph type=text name=ap_hostname value='%s' " \
    "placeholder='esp32-nat-router' maxlength=32 pattern='[A-Za-z0-9-]*'>" \
    "<label for=apd>DNS server</label>" \
    "<input id=apd type=text name=ap_dns value='%s' " \
    "placeholder='empty follows the uplink'>" \
    "<label for=apm>MAC address</label>" \
    "<input id=apm type=text name=ap_mac value='%s' placeholder='AA:BB:CC:DD:EE:FF'>" \
    CONFIG_AP_CHANNEL \
    "<label for=apa>Security</label>" \
    "<select id=apa name=ap_auth><option value=0 %s>WPA2 and WPA3</option>" \
    "<option value=1 %s>WPA2 only</option>" \
    "<option value=2 %s>WPA3 only</option></select>" \
    "<label>Options</label><div>" \
    "<label><input type=checkbox name=ap_nat value=1 %s>Share the uplink (NAT)</label><br>" \
    "<label><input type=checkbox name=ap_enabled value=1 %s>Broadcast this network</label><br>" \
    "<label><input type=checkbox id=apo name=ap_open value=1 %s>Open, no password</label><br>" \
    "<label><input type=checkbox name=ap_hidden value=1 %s>Hide the name</label></div>" \
    "<button class=\"b p act\" type=submit>Save and restart</button>" \
    "</div></form></details>"

/* Uplink ------------------------------------------------------------------ */

#if CONFIG_ETH_UPLINK

#define CONFIG_STA "<details><summary>Uplink</summary>" \
    "<table class=\"t kv\"><tbody><tr><td>Mode</td><td>Ethernet (LAN8720)</td>" \
    "</tr></tbody></table></details>"

#else

#if WIFI_HAS_5GHZ
/* Substitutes: three band selections. */
#define CONFIG_STA_BAND "<label for=stb>Band</label>" \
    "<select id=stb name=sta_band><option value=0 %s>Whichever is stronger</option>" \
    "<option value=1 %s>2.4 GHz only</option>" \
    "<option value=2 %s>5 GHz only</option></select>"
#else
#define CONFIG_STA_BAND ""
#endif

/* Substitutes: ssid, [three band selections,] username, identity, four TTLS
 * selections, cert-bundle and time-check states, MAC.
 *
 * The EAP method dropdown that used to sit above TTLS Phase 2 is gone: the
 * value was stored and displayed but never handed to esp_eap_client, which
 * negotiates the method with the server itself. A control that cannot affect
 * anything is worse than no control.
 */
#define CONFIG_STA "<details><summary>Uplink</summary>" \
    "<form action=/config method=GET><div class=f>" \
    "<label for=sts>Network name</label>" \
    "<input id=sts type=text name=ssid value='%s' placeholder='Network to join'>" \
    "<label for=stp>Password</label>" \
    "<input id=stp type=password name=password placeholder='unchanged'>" \
    CONFIG_STA_BAND \
    "<p class=hint>Pick one from <a href=/scan>Scan</a> to fill this in.</p>" \
    "<label for=stm>MAC address</label>" \
    "<input id=stm type=text name=sta_mac value='%s' placeholder='AA:BB:CC:DD:EE:FF'>" \
    "<p class=\"full n\" style=margin-top:8px>WPA2 Enterprise, if the network " \
    "needs it</p>" \
    "<label for=stu>Username</label>" \
    "<input id=stu type=text name=ent_username value='%s' placeholder='optional'>" \
    "<label for=sti>Identity</label>" \
    "<input id=sti type=text name=ent_identity value='%s' " \
    "placeholder='defaults to the username'>" \
    "<label for=stt>TTLS phase 2</label>" \
    "<select id=stt name=ttls_phase2><option value=0 %s>MSCHAPv2</option>" \
    "<option value=1 %s>MSCHAP</option><option value=2 %s>PAP</option>" \
    "<option value=3 %s>CHAP</option></select>" \
    "<label>Certificates</label><div>" \
    "<label><input type=checkbox name=cert_bundle value=1 %s>Trust the built-in CA bundle</label><br>" \
    "<label><input type=checkbox name=no_time_chk value=1 %s>Skip the expiry check</label></div>" \
    "<button class=\"b p act\" type=submit>Save and restart</button>" \
    "</div></form></details>"

#endif /* CONFIG_ETH_UPLINK */

/* Uplink addressing -------------------------------------------------------
 * Substitutes: address, netmask, gateway. */
#define CONFIG_STATIC "<details><summary>Uplink address</summary>" \
    "<form action=/config method=GET><div class=f>" \
    "<label for=sip>Address</label>" \
    "<input id=sip type=text name=staticip value='%s' placeholder='from DHCP'>" \
    "<label for=smk>Netmask</label>" \
    "<input id=smk type=text name=subnetmask value='%s' placeholder='255.255.255.0'>" \
    "<label for=sgw>Gateway</label>" \
    "<input id=sgw type=text name=gateway value='%s' placeholder='192.168.1.1'>" \
    "<p class=hint>Leave all three empty to use DHCP.</p>" \
    "<button class=\"b p act\" type=submit>Save and restart</button>" \
    "</div></form></details>"

/* Remote console ----------------------------------------------------------
 * Substitutes: two service selections, status class, status text, the kick
 * button (or an empty string), port, three bind states, idle timeout. */
#define CONFIG_RC "<details><summary>Remote console</summary>" \
    "<form action=/config method=GET><input type=hidden name=rc_save value=1>" \
    "<div class=f>" \
    "<label for=rce>Service</label>" \
    "<select id=rce name=rc_enabled><option value=1 %s>Enabled</option>" \
    "<option value=0 %s>Disabled</option></select>" \
    "<label>Status</label><div><span class=\"%s\">%s</span>%s</div>" \
    "<label for=rcp>Port</label>" \
    "<input id=rcp type=number name=rc_port value='%d' min=1 max=65535>" \
    "<label>Reachable on</label><div>" \
    "<label><input type=checkbox name=rc_bind_ap value=1 %s>AP</label> " \
    "<label><input type=checkbox name=rc_bind_sta value=1 %s>" RC_UPLINK_LABEL "</label> " \
    "<label><input type=checkbox name=rc_bind_vpn value=1 %s>VPN</label></div>" \
    "<label for=rct>Idle timeout</label>" \
    "<input id=rct type=number name=rc_timeout value='%lu' min=0 max=86400>" \
    "<p class=hint>Seconds before an idle session is dropped; 0 never drops one.</p>" \
    "<button class=\"b p act\" type=submit>Save</button>" \
    "</div></form></details>"

/* Packet capture ----------------------------------------------------------
 * Substitutes: three mode selections, client class, client text, captured,
 * dropped, snaplen, the address to point the capture tool at. */
#define CONFIG_PCAP "<details><summary>Packet capture</summary>" \
    "<form action=/config method=GET><input type=hidden name=pcap_save value=1>" \
    "<div class=f>" \
    "<label for=pcm>Mode</label>" \
    "<select id=pcm name=pcap_mode><option value=off %s>Off</option>" \
    "<option value=acl %s>Rules marked for capture</option>" \
    "<option value=promisc %s>Everything</option></select>" \
    "<label>Client</label><div><span class=\"%s\">%s</span></div>" \
    "<label>Packets</label><div>%lu captured, %lu dropped</div>" \
    "<label for=pcs>Bytes per packet</label>" \
    "<input id=pcs type=number name=pcap_snaplen value='%d' min=64 max=1600>" \
    "<p class=hint>Read it with <code>nc %s 19000 | wireshark -k -i -</code></p>" \
    "<button class=\"b p act\" type=submit>Save</button>" \
    "</div></form></details>"

/* Firmware ----------------------------------------------------------------
 * Substitutes: running partition, chip, version, build date, build time. */
#define CONFIG_FIRMWARE "<details><summary>Firmware</summary>" \
    "<table class=\"t kv\"><tbody>" \
    "<tr><td>Running from</td><td>%s</td></tr>" \
    "<tr><td>Chip</td><td>%s</td></tr>" \
    "<tr><td>Version</td><td>%s</td></tr>" \
    "<tr><td>Built</td><td>%s %s</td></tr>" \
    "</tbody></table><div class=f>" \
    "<label for=otf>New image</label>" \
    "<input id=otf type=file accept=.bin>" \
    "<button class=\"b p act\" type=button id=otb>Upload and restart</button>" \
    "<p class=hint id=otm></p></div></details>"

#define CONFIG_BACKUP "<details><summary>Backup and restore</summary>" \
    "<div class=f>" \
    "<label for=exp>Export passphrase</label>" \
    "<input id=exp type=password placeholder='empty writes plain JSON'>" \
    "<button class=\"b act\" type=button id=exb>Download settings</button>" \
    "<p class=hint id=exm>Passwords and keys are only included when a " \
    "passphrase encrypts the file.</p>" \
    "<label for=imf>Settings file</label>" \
    "<input id=imf type=file accept=.json>" \
    "<label for=imp>Its passphrase</label>" \
    "<input id=imp type=password placeholder='if it is encrypted'>" \
    "<button class=\"b act\" type=button id=imb>Restore and restart</button>" \
    "<p class=hint id=imm></p></div></details>"

/* Reboot and access -------------------------------------------------------
 * Substitutes: three web-bind states. */
#define CONFIG_DANGER "<details><summary>Reboot and access</summary>" \
    "<form action=/config method=GET><div class=f>" \
    "<label>Restart</label>" \
    "<button class=\"b d\" type=submit name=reset value=1 " \
    "data-c='Restart the router now?'>Reboot</button>" \
    "</div></form>" \
    "<p class=\"al wn\">Both settings below can lock you out of this page. " \
    "The console can undo either: <code>web_ui bind all</code> and " \
    "<code>web_ui enable</code>.</p>" \
    "<form action=/config method=GET>" \
    "<input type=hidden name=web_bind_save value=1><div class=f>" \
    "<label>Web UI reachable on</label><div>" \
    "<label><input type=checkbox name=web_bind_ap value=1 %s>AP</label> " \
    "<label><input type=checkbox name=web_bind_sta value=1 %s>" RC_UPLINK_LABEL "</label> " \
    "<label><input type=checkbox name=web_bind_vpn value=1 %s>VPN</label></div>" \
    "<button class=\"b d act\" type=submit " \
    "data-c='Save? If you are not on one of the interfaces you ticked, this " \
    "page becomes unreachable.'>Save access</button>" \
    "</div></form>" \
    "<form action=/config method=GET><div class=f>" \
    "<label>Web UI</label>" \
    "<button class=\"b d\" type=submit name=disable_interface value=1 " \
    "data-c='Turn the web interface off? Only the console can turn it back " \
    "on.'>Turn off</button>" \
    "</div></form></details>"
