// ligo admin UI (§7.4): attaches the session's CSRF token to every htmx
// request and shows a banner for server errors, which htmx does not swap.
// DOM APIs and textContent only, never an HTML sink.
(function () {
  'use strict';

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function showError(message) {
    var banner = document.getElementById('error-banner');
    if (!banner) {
      return;
    }
    banner.textContent = message;
    banner.hidden = false;
  }

  document.addEventListener('htmx:config:request', function (evt) {
    var token = csrfToken();
    if (token) {
      evt.detail.ctx.request.headers['X-CSRF-Token'] = token;
    }
  });

  document.addEventListener('htmx:response:error', function (evt) {
    var response = evt.detail.ctx.response;
    if (!response || response.status < 500) {
      return; // 4xx fragments are swapped into the form's or the page's error container
    }
    var id = response.headers.get('X-Request-Id') || 'unknown';
    showError('The server could not complete the request (' + response.status + '). Request ID: ' + id + '.');
  });

  document.addEventListener('htmx:error', function () {
    showError('The request could not be sent. Check the connection and try again.');
  });
})();
