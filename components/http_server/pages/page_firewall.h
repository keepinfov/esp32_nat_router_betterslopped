/* Firewall (ACL) page fragments.
 *
 * Chrome comes from page_common.h through send_page_head() / send_page_foot().
 *
 * The rule table used to carry nine columns — address and port were separate
 * for both ends, and a "#" column repeated what the row's own position already
 * said. Address and port are one endpoint as far as a reader is concerned, so
 * they are printed as one ("10.0.0.0/8:any"), which brings the table down to
 * six columns and lets it fit a phone.
 *
 * The error message used to be a modal overlay with its own stylesheet, its own
 * dismiss button and an inline history.replaceState() call. It is an alert at
 * the top of the page now.
 */

#define FIREWALL_INTRO "<p class=\"al\">Rules are matched from the top down and " \
    "the first match wins. A packet that matches nothing is allowed.</p>"

/* Substitutes: escaped message. */
#define FIREWALL_ERROR "<p class=\"al er\">%s</p>"

/* Substitutes: list description, list number, allowed, denied, no-match.
 * The Clear button is emitted before the counters it sits beside: a float that
 * follows text on the same line drops below it instead of pulling right.  It is
 * a form rather than a link because it changes something, and it lives in a div
 * rather than a p because a p is closed by the first block element inside it. */
#define FIREWALL_LIST_OPEN "<div class=c><h2>%s</h2>" \
    "<div class=n><form method=post action=/firewall style=float:right>" \
    "<button class=\"b s d\" name=clear_acl value=%d " \
    "data-c='Delete every rule in this list?'>Clear</button></form>" \
    "%lu allowed &middot; %lu denied &middot; %lu unmatched</div>" \
    "<div class=tw><table class=\"t r\"><thead><tr>" \
    "<th>Source</th><th>Destination</th><th>Protocol</th>" \
    "<th>Action</th><th>Hits</th><th></th>" \
    "</tr></thead><tbody>"

#define FIREWALL_LIST_EMPTY "<tr><td colspan=6 class=n>No rules; " \
    "everything is allowed.</td></tr>"

#define FIREWALL_LIST_CLOSE "</tbody></table></div></div>"

/* The direction options are filled in from acl_get_desc(), the same strings the
 * cards above and the console's "acl" command use — spelling them out a second
 * time here is how a renamed list ends up meaning two different things. */
#define FIREWALL_ADD_OPEN "<form action=/firewall method=POST>" \
    "<div class=c><h2>Add a rule</h2><div class=f>" \
    "<label for=fl>Direction</label><select id=fl name=acl_list>"

/* Substitutes: list number, list description. */
#define FIREWALL_ADD_OPTION "<option value=%d>%s</option>"

#define FIREWALL_ADD_REST "</select>" \
    "<label for=fp>Protocol</label>" \
    "<select id=fp name=proto><option value=0>Any</option>" \
    "<option value=6>TCP</option><option value=17>UDP</option>" \
    "<option value=1>ICMP</option></select>" \
    "<label for=fsi>Source</label>" \
    "<input id=fsi type=text name=src_ip placeholder='any, IP/CIDR, or device name'>" \
    "<label for=fsp>Source port</label>" \
    "<input id=fsp type=text name=src_port placeholder='any'>" \
    "<label for=fdi>Destination</label>" \
    "<input id=fdi type=text name=dst_ip placeholder='any, IP/CIDR, or device name'>" \
    "<label for=fdp>Destination port</label>" \
    "<input id=fdp type=text name=dst_port placeholder='any'>" \
    "<label for=fa>Action</label>" \
    "<select id=fa name=action><option value=1>Allow</option>" \
    "<option value=0>Deny</option>" \
    "<option value=3>Allow and capture</option>" \
    "<option value=2>Deny and capture</option></select>" \
    "<button class=\"b p act\" type=submit name=acl_action value='Add Rule'" \
    ">Add rule</button>" \
    "</div></div></form>"
