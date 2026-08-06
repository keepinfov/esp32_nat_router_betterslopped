/* WireGuard VPN page fragments.
 *
 * Chrome comes from page_common.h through send_page_head() / send_page_foot().
 * What is left here is the status readout, the settings form and the .conf
 * import box.
 *
 * Two things this page used to carry are gone. The inline stylesheet is now
 * /app.css, shared with every other page. And the "Settings saved, rebooting"
 * banner used to be a script that inspected window.location.search and blanked
 * the body — the handler is the one that queues the restart, so it says so
 * itself and the page needs no JavaScript for that at all.
 */

#define VPN_REBOOT_NOTE "<p class=\"al ok\">Settings saved. The router is " \
    "restarting; this page comes back once it is up again.</p>"

#define VPN_STATUS_OPEN "<div class=c><h2>Status</h2><table class=\"t kv\"><tbody>"
#define VPN_STATUS_CLOSE "</tbody></table></div>"

#define VPN_FORM_OPEN "<form action=/vpn method=POST>" \
    "<div class=c><h2>Tunnel</h2><div class=f>"

/* Between this router's own settings and the remote peer's.  One card, two
 * headings: the Save button belongs to both halves, and a second card would
 * have put it visually inside the peer settings alone. */
#define VPN_FORM_MID "</div><h2>Peer</h2><div class=f>"

#define VPN_FORM_CLOSE "<button class=\"b p act\" type=submit>" \
    "Save and restart</button></div></div></form>"

/* The import box is the one part of the page that needs JavaScript; without it
 * the fields above still work, which is why it sits below them rather than
 * above. The click handler lives in app.js, where it costs nothing in flash.
 * &#10; is a newline inside the placeholder attribute. */
#define VPN_IMPORT "<div class=c><h2>Import a configuration</h2>" \
    "<p class=n>Paste a WireGuard <code>.conf</code>. The fields above are " \
    "filled in from it and the router restarts.</p>" \
    "<textarea id=wgc rows=8 placeholder='[Interface]&#10;PrivateKey = ...&#10;" \
    "Address = 10.2.0.2/32&#10;&#10;[Peer]&#10;PublicKey = ...&#10;" \
    "Endpoint = host:51820'></textarea>" \
    "<p style=margin-top:8px><button class=b type=button id=wgb>Import and " \
    "restart</button> <span id=wgm class=n></span></p></div>"
