/* Progressive enhancement only: every form on this device submits and every
 * link works with JavaScript disabled. Nothing here is required for the router
 * to be configurable — the captive-portal path in particular must not depend
 * on it. */
'use strict';

/* Confirmation for destructive submits. The button carries the question in
 * data-c, so the markup stays one attribute instead of an inline handler. */
document.addEventListener('click', function (e) {
  var el = e.target.closest('[data-c]');
  if (el && !confirm(el.getAttribute('data-c'))) e.preventDefault();
});

/* "Reserve" on the Mappings page copies a connected client into the
 * reservation form below the table. The values ride in data-* attributes
 * rather than an inline onclick, so the firmware escapes them once, for HTML,
 * instead of once for HTML and again for a JavaScript string literal. */
document.addEventListener('click', function (e) {
  var el = e.target.closest('[data-m]');
  if (!el) return;
  var mac = document.getElementById('rmac');
  mac.value = el.getAttribute('data-m');
  document.getElementById('rip').value = el.getAttribute('data-i');
  document.getElementById('rname').value = el.getAttribute('data-n');
  mac.scrollIntoView({ block: 'center' });
});

/* Guard against double submission: a second click on "Save & Reboot" used to
 * fire a second request. */
document.addEventListener('submit', function (e) {
  var b = e.target.querySelector('button[type=submit], input[type=submit]');
  if (b) setTimeout(function () { b.disabled = true; }, 0);
});

/* WireGuard .conf import, VPN page only. A shortcut, not the only way in: the
 * same settings are on the form above it, so nothing is lost without this.
 * The script tag is deferred, so the elements exist by the time this runs. */
var wgb = document.getElementById('wgb');
if (wgb) wgb.onclick = function () {
  var text = document.getElementById('wgc').value;
  var out = document.getElementById('wgm');
  if (!text.trim()) { out.textContent = 'Paste a configuration first.'; return; }
  out.textContent = 'Importing…';
  fetch('/api/vpn-import', { method: 'POST', body: text })
    .then(function (r) { return r.json(); })
    .then(function (d) { out.textContent = d.msg || (d.ok ? 'Imported.' : 'Import failed.'); })
    .catch(function () { out.textContent = 'Request failed.'; });
};

/* Config page: firmware upload, settings export, settings import.
 *
 * These three used to be ~4 KB of JavaScript inside a C string literal in
 * page_config.h, which is 4 KB of flash — the one place in this project where
 * bytes are genuinely scarce. Here they are minified and gzipped with the rest
 * of the file. Each one binds by id and does nothing on the pages that lack it.
 */
function bind(id, fn) {
  var el = document.getElementById(id);
  if (el) el.onclick = fn;
}

/* The firmware image is sent as the raw request body, not a form field: the
 * OTA handler streams it straight into the inactive partition. */
bind('otb', function () {
  var file = document.getElementById('otf').files[0];
  var out = document.getElementById('otm');
  if (!file) { out.textContent = 'Choose a .bin file first.'; return; }
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/ota-upload');
  xhr.upload.onprogress = function (ev) {
    if (ev.lengthComputable) {
      out.textContent = 'Uploading ' + Math.round(ev.loaded / ev.total * 100) + '%';
    }
  };
  xhr.onload = function () {
    var d = null;
    try { d = JSON.parse(xhr.responseText); } catch (err) { /* not JSON */ }
    out.textContent = d && d.ok
      ? 'Installed. The router is restarting with the new firmware.'
      : (d && d.msg) || 'Upload failed.';
  };
  xhr.onerror = function () { out.textContent = 'Upload failed: connection lost.'; };
  xhr.send(file);
});

bind('exb', function () {
  var pass = document.getElementById('exp').value;
  var out = document.getElementById('exm');
  out.textContent = 'Preparing…';
  fetch('/api/config-export', {
    method: 'POST',
    body: JSON.stringify({ pass: pass }),
    headers: { 'Content-Type': 'application/json' }
  }).then(function (res) {
    if (!res.ok) return res.text().then(function (t) { throw new Error(t); });
    /* Split rather than match: pack_asset.py's minifier tracks string literals
     * but not regex literals, so a regex containing a quote confuses it. */
    var cd = (res.headers.get('Content-Disposition') || '').split('filename="')[1];
    var name = cd ? cd.split('"')[0] : 'esp32_nat_config.json';
    return res.blob().then(function (b) {
      var url = URL.createObjectURL(b);
      var a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 100);
      out.textContent = pass ? 'Downloaded, encrypted.' : 'Downloaded as plain JSON.';
    });
  }).catch(function () { out.textContent = 'Export failed.'; });
});

bind('imb', function () {
  var file = document.getElementById('imf').files[0];
  var pass = document.getElementById('imp').value;
  var out = document.getElementById('imm');
  if (!file) { out.textContent = 'Choose a settings file first.'; return; }
  var reader = new FileReader();
  reader.onload = function () {
    out.textContent = 'Restoring…';
    var headers = { 'Content-Type': 'application/json' };
    if (pass) headers['X-Config-Pass'] = pass;
    fetch('/api/config-import', { method: 'POST', body: reader.result, headers: headers })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        out.textContent = d.ok
          ? 'Restored. The router is restarting.'
          : d.msg || 'Restore failed.';
      })
      .catch(function () { out.textContent = 'Restore failed.'; });
  };
  reader.readAsText(file);
});

/* The "open network" checkbox and the access-point password contradict each
 * other; keeping them in sync means a submitted form cannot mean both. */
var apOpen = document.getElementById('apo');
var apPass = document.getElementById('apw');
if (apOpen && apPass) {
  apOpen.addEventListener('change', function () { if (apOpen.checked) apPass.value = ''; });
  apPass.addEventListener('input', function () { apOpen.checked = false; });
}
