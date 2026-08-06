# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working with code in this
repository.

## What this is

ESP32 NAT router firmware built on ESP-IDF 5.5. An AP interface is bridged to a
WiFi STA, Ethernet, or WireGuard uplink with NAT. Configuration happens through
a web UI, a serial console, or an optional TCP console.

- `main/` — startup, WiFi/Ethernet event handling, NAT hooks, DHCP, VPN, LED
- `components/http_server/` — web UI: handlers in `http_server.c`, page
  fragments in `pages/`, static assets in `www/`
- `components/cmd_router/`, `cmd_system/` — console commands and the NVS
  configuration helpers (`get_config_param_*`) that the web UI also calls
- `components/acl/`, `pcap_capture/`, `syslog/`, `mqtt_ha/`, `oled_display/`,
  `remote_console/` — optional features
- `components/dhcpserver/` — fork of the IDF component, adds MAC reservations
  and hostname capture
- `esp_nat_bridge.py` — MCP bridge that drives the router over its TCP console

## Flash budget — read this before adding anything

`ota_0` is 1536 KiB (`partitions_example.csv`). The ESP32-C3 and ESP32-C5
images have run within a few kilobytes of that ceiling, which is why
`build_all_targets.sh` fails the build past 95%. Before adding a feature, check
`idf.py size` and `idf.py size-components`, and prefer making a new subsystem
conditional over compiling it unconditionally.

Two things cost more than they look: log strings — the shared
`sdkconfig.defaults` sets `LOG_DEFAULT_LEVEL_WARN` so `ESP_LOGI` is compiled
out entirely — and anything embedded as a C array. Static web assets belong in
`components/http_server/www/`, where the build gzips and embeds them.

### No floating point in printf

`sdkconfig.defaults` sets `LIBC_NEWLIB_NANO_FORMAT`, which links the
printf/scanf already sitting in ROM. That build has neither floating-point nor
64-bit conversions: a `%f` or a `%llu` compiles fine and prints nothing useful.
Format tenths by hand (`"%u.%u", v / 10, v % 10`) — `format_bytes_human()` and
`TX_DBM_WHOLE`/`TX_DBM_CENTS` in `router_config.h` are the existing examples.
The C6 is the exception and turns the option back off: its ROM carries the full
versions instead, so nano there adds a second copy rather than removing one.

### Optimisation is split on purpose

The global default is `-O2` (`COMPILER_OPTIMIZATION_PERF`). Components on the
control plane — `main`, `http_server`, `cmd_router`, `cmd_system`, and the
optional subsystems — override it to `-Os` in their own `CMakeLists.txt`. The
packet path (`acl`, `dhcpserver`, `pcap_capture`) stays at `-O2`.

Switching the global default to `-Os` measures 120 416 bytes smaller on the
C3, and it is deliberately not done: it would take lwIP, the WiFi stack and the
NAT hooks with it, and nobody has measured what that does to throughput. If
you need the space, that is where it is — with an iperf3 run attached.

### Leaving a subsystem out

MQTT, the remote console, packet capture, syslog and the OLED driver each have
a Kconfig option under "Optional subsystems", all default `y`. Turning one off
compiles its component to nothing; its header supplies do-nothing inlines so no
caller needs an `#ifdef`. Measured on the C3: MQTT 57.3 KB, OLED 18.8 KB,
remote console 5.5 KB, packet capture 4.7 KB, syslog 3.1 KB.

Two traps when adding another one. `REQUIRES` must stay unconditional —
ESP-IDF collects component requirements before it reads sdkconfig, so a
`CONFIG_`-dependent list comes out empty and the include paths vanish even in
the build where the feature is on. And `target_compile_options(... PRIVATE)`
has to be guarded too: a component with no sources is an INTERFACE target,
where PRIVATE options are a CMake error.

## Building

```bash
idf.py set-target esp32c3
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.esp32c3" build
```

All targets at once: `./build_all_targets.sh`. Each target has its own build
directory, its own `sdkconfig`, and an entry in `TARGET_SDKCONFIG` — a target
without one silently loses its overrides. Ethernet boards additionally take
`sdkconfig.defaults.eth_common`.

## Web UI conventions

- One stylesheet, `components/http_server/www/app.css`, served gzipped at
  `/app.css`. Do not add `<style>` blocks to page templates.
- Assets in `www/` are minified by `pack_asset.py` before they are gzipped and
  embedded, so comments and indentation there cost nothing in flash — write
  them freely. The C page fragments in `pages/` are a different matter: those
  string literals go into the image verbatim.
- Shared chrome comes from `send_page_head()` / `send_page_foot()`; a page
  emits only its own body.
- Table classes: `.t` is any table, `.t.kv` a key/value readout, `.t.r` a
  record list that reflows below 640px into one compact block per row — first
  cell as the heading, the rest joined into one muted line. Mark the cell
  holding a row's button `class=a` so it stays on its own line, right-aligned.
  A reflowed table drops its column headings, so a value that is ambiguous
  without one has to carry the word itself ("1284 hits", not "1284").
- Templates are printf format strings. A fragment with no substitutions goes to
  `SEND_CHUNK` verbatim; only fragments with real conversions go through
  `snprintf`. That is what keeps doubled `%%` escapes out of the markup.
- `SEND_CHUNK` returns on the first failed chunk, so a handler must not hold a
  heap allocation across a chunk loop — free it first, or use a local macro
  that releases it on the way out (see `scan_get_handler`).
- Anything originating outside the firmware — client hostnames, query
  parameters, stored configuration — must be escaped or filtered before it
  reaches a page.
- Anything that changes state is a POST. A page handler calls `take_form()`
  first: on GET it yields a NULL form and the page just renders; on POST it
  checks the request's origin, reads the body, and hands back a buffer that
  `httpd_query_key_value()` parses exactly like a query string. Query
  parameters are for reads only — an error message to display, an SSID to
  pre-fill. That includes row actions: a Delete button is a one-button form,
  not a link.
- `SEND_RENDERED(req, buf, n)` rather than `SEND_CHUNK(req, buf, n)` after an
  `snprintf`. snprintf returns the length it wanted, not the length it wrote.

## Code exploration

Prefer the jCodemunch MCP tools (`get_file_outline`, `search_symbols`,
`get_repo_outline`) when they are available in the session: call `resolve_repo`
on the working directory first, and `index_folder` if the repository is not
indexed yet. When those tools are not present — which is the common case — the
built-in Read, Grep, and Glob tools are the intended fallback, not a violation.
