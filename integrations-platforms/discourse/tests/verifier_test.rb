# frozen_string_literal: true

# The plain-ruby test of the kiwi verify client. Run:
#   ruby tests/verifier_test.rb
require "json"
require "net/http"
require_relative "../lib/kiwi_captcha/verifier"

$failures = 0
$checks = 0

def check(name, condition)
  $checks += 1
  return if condition

  $failures += 1
  warn "FAIL: #{name}"
end

# Token resolution: the collect/distinct/conflict authority rule.
check("header token", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => " hdr " }, cookies: {}
) == { token: "hdr", code: nil })
check("cookie token", KiwiCaptcha::Verifier.resolve_token(
  headers: {}, cookies: { "kiwi_token" => "c" }
) == { token: "c", code: nil })
check("no token", KiwiCaptcha::Verifier.resolve_token(
  headers: {}, cookies: {}
) == { token: nil, code: nil })
check("blank header and cookie are no token", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "  " }, cookies: { "kiwi_token" => "" }
) == { token: nil, code: nil })

# The ambiguity matrix: zero distinct values pass nothing, one distinct
# value verifies however many sources carry it, two distinct values
# conflict with the typed code before any verification.
check("header a cookie a verifies", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a" }, cookies: { "kiwi_token" => "a" }
) == { token: "a", code: nil })
check("header a cookie b conflicts", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a" }, cookies: { "kiwi_token" => "b" }
) == { token: nil, code: :token_source_conflict })
check("two distinct header lines conflict", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a\nb" }, cookies: {}
) == { token: nil, code: :token_source_conflict })
check("two header lines carrying the same value verify", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a\na" }, cookies: {}
) == { token: "a", code: nil })
check("a comma-joined header line splits into values", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a, b" }, cookies: {}
) == { token: nil, code: :token_source_conflict })
check("a comma-joined header line with one value verifies", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a, a" }, cookies: {}
) == { token: "a", code: nil })
check("distinct values across the comma split and the cookie conflict", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => "a\n a" }, cookies: { "kiwi_token" => "b" }
) == { token: nil, code: :token_source_conflict })
check("whitespace-padded equal values are one distinct value", KiwiCaptcha::Verifier.resolve_token(
  headers: { "HTTP_X_KIWI_TOKEN" => " a " }, cookies: { "kiwi_token" => "a " }
) == { token: "a", code: nil })

# Client ip.
check("peer ip untrusted", KiwiCaptcha::Verifier.client_ip(
  { "REMOTE_ADDR" => "10.9.9.9", "HTTP_X_FORWARDED_FOR" => "1.2.3.4" }
) == "10.9.9.9")
check("peer ip trusted list empty", KiwiCaptcha::Verifier.client_ip(
  { "REMOTE_ADDR" => "10.9.9.9", "HTTP_X_FORWARDED_FOR" => "1.2.3.4" }, ""
) == "10.9.9.9")
check("forwarded ip trusted", KiwiCaptcha::Verifier.client_ip(
  { "REMOTE_ADDR" => "10.0.0.1", "HTTP_X_FORWARDED_FOR" => "1.2.3.4, 10.0.0.1" }, "10.0.0.0/8"
) == "1.2.3.4")
check("client-supplied leftmost entry is ignored", KiwiCaptcha::Verifier.client_ip(
  { "REMOTE_ADDR" => "10.0.0.1", "HTTP_X_FORWARDED_FOR" => "6.6.6.6, 1.2.3.4, 10.0.0.1" }, "10.0.0.0/8"
) == "1.2.3.4")
check("garbage hop fails closed", KiwiCaptcha::Verifier.client_ip(
  { "REMOTE_ADDR" => "10.0.0.1", "HTTP_X_FORWARDED_FOR" => "1.2.3.4, garbage!!, 10.0.0.1" }, "10.0.0.0/8"
) == "10.0.0.1")

# The wire request.
request = KiwiCaptcha::Verifier.build_request(
  verify_url: "http://127.0.0.1:7371/verify", token: "t", scope: "signup",
  ip: "192.0.2.1", bearer: "b",
)
body = JSON.parse(request[:body])
check("request body shape", body["token"] == "t" && body["scope"] == "signup" && body["remoteip"] == "192.0.2.1")
check("bearer header", request[:headers]["Authorization"] == "Bearer b")

# The decision table over a fake transport.
settings = { verify_url: "http://x", bearer: "", trusted_proxies: "" }
check("success verifies", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 200, body: '{"success":true}' } }
) == { ok: true, code: :verified })
check("failed challenge denies", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 200, body: '{"success":false,"error-codes":["timeout-or-duplicate"]}' } }
) == { ok: false, code: :challenge_failed })
check("5xx is a fault", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 502, body: "" } }
) == { ok: false, code: :unavailable })
check("garbage body is unreadable", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 200, body: "<html>" } }
) == { ok: false, code: :unreadable })
check("302 with success body fails closed", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 302, body: '{"success":true}' } }
) == { ok: false, code: :challenge_failed })
check("403 with success body fails closed", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 403, body: '{"success":true}' } }
) == { ok: false, code: :challenge_failed })
check("199 with success body fails closed", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 199, body: '{"success":true}' } }
) == { ok: false, code: :challenge_failed })
check("204 with success body passes", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { { status: 204, body: '{"success":true}' } }
) == { ok: true, code: :verified })
check("a raising transport is a fault, never an open gate", KiwiCaptcha::Verifier.decide(
  token: "t", scope: "login", settings: settings, server: {},
  transport: ->(_r) { raise IOError, "down" }
) == { ok: false, code: :unavailable })
check("missing peer fails closed", KiwiCaptcha::Verifier.client_ip({}, []) == "")
check("garbage peer fails closed", KiwiCaptcha::Verifier.client_ip({ "REMOTE_ADDR" => "not-an-ip" }, []) == "")

# The real transport against a handcrafted local HTTP server.
require "socket"
server = TCPServer.new("127.0.0.1", 0)
port = server.addr[1]
thread = Thread.new do
  socket = server.accept
  request = +""
  while (line = socket.gets) && line != "\r\n"
    request << line
  end
  content_length = request[/Content-Length: (\d+)/i, 1].to_i
  request << socket.read(content_length) if content_length.positive?
  ok = request.include?("good-token")
  socket.write(
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n" \
    "Content-Length: #{ok ? 16 : 17}\r\n\r\n" +
    (ok ? '{"success":true} ' : '{"success":false} '),
  )
  socket.close
end
answer = nil
# The module ships no default transport (the middleware carries it);
# exercise Net::HTTP directly to prove the request shape works.
http = Net::HTTP.new("127.0.0.1", port)
wire = KiwiCaptcha::Verifier.build_request(
  verify_url: "http://127.0.0.1:#{port}/verify", token: "good-token",
  scope: "signup", ip: "192.0.2.1", bearer: "",
)
response = http.post("/verify", wire[:body], wire[:headers])
thread.join
server.close
check("real http round trip verifies", response.code.to_i == 200 && JSON.parse(response.body)["success"] == true)

puts "#{$checks} checks, #{$failures} failures"
exit($failures.zero? ? 0 : 1)
