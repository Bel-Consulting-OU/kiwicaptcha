// The client half of the kiwi-captcha plugin: adds the X-Kiwi-Token
// header to the sign-up POSTs so the server-side gate sees the token
// the shim widget produced. Loaded through register_asset; the admin
// adds the shim script tag itself (Admin, Customize, Themes, edit the
// common </head> section) pointing at the deployment's compat route,
// e.g.:
//   <script src="https://kiwi.example.com/kiwi-captcha/api.js?compat=recaptcha" defer></script>
(function () {
  "use strict";

  function readToken() {
    var field = document.querySelector("[data-kiwi-token]");
    if (field && field.value && field.value.trim()) return field.value.trim();
    var match = document.cookie.match(/(?:^|;\s*)kiwi_token=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      var url = typeof input === "string" ? input : (input && input.url) || "";
      var method = ((init && init.method) || "GET").toUpperCase();
      if (
        method === "POST" &&
        window.Discourse &&
        window.Discourse.__container__ &&
        /^\/u(\.json)?(\/|$)/.test(url.replace(/^https?:\/\/[^/]+/, ""))
      ) {
        var token = readToken();
        if (token) {
          init = init || {};
          init.headers = new Headers((init && init.headers) || {});
          init.headers.set("X-Kiwi-Token", token);
        }
      }
    } catch (e) {
      // never break the request on a header helper failure
    }
    return origFetch.call(window, input, init);
  };
})();
