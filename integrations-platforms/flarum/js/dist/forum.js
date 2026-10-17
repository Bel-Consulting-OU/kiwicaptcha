// The client half of kiwi/flarum-captcha: a plain, build-free forum
// asset. The admin points the deployment's shim script at the forum
// (an html block via a "Headers" style extension or the custom less /
// footer setting); this asset makes every registration fetch carry
// the X-Kiwi-Token header the api middleware requires, reading the
// token the shim widget wrote.
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
      var path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
      if (method === "POST" && (path === "/api/register" || path === "/register")) {
        var token = readToken();
        if (token) {
          init = init || {};
          var headers = new Headers((init && init.headers) || {});
          headers.set("X-Kiwi-Token", token);
          init.headers = headers;
        }
      }
    } catch (e) {
      // never break the request on a header helper failure
    }
    return origFetch.call(window, input, init);
  };
})();
