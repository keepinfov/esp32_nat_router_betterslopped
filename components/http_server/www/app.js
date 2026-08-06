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

/* Guard against double submission: a second click on "Save & Reboot" used to
 * fire a second request. */
document.addEventListener('submit', function (e) {
  var b = e.target.querySelector('button[type=submit], input[type=submit]');
  if (b) setTimeout(function () { b.disabled = true; }, 0);
});

/* Shared by the OTA and config-import forms. */
window.upload = function (form, url, status) {
  var out = document.getElementById(status);
  var xhr = new XMLHttpRequest();
  xhr.open('POST', url);
  xhr.upload.onprogress = function (ev) {
    if (ev.lengthComputable) {
      out.textContent = 'Uploading ' + Math.round(ev.loaded / ev.total * 100) + '%';
    }
  };
  xhr.onload = function () {
    out.textContent = xhr.status === 200 ? xhr.responseText : 'Failed: ' + xhr.responseText;
  };
  xhr.onerror = function () { out.textContent = 'Upload failed: connection lost'; };
  xhr.send(new FormData(form));
  return false;
};
