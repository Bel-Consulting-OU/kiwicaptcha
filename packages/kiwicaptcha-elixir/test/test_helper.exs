# The Redis suite gate. The :redis-tagged tests in redis_test.exs run
# live against a reachable server; when none is reachable they are
# excluded here, before ExUnit.start, because ExUnit has no runtime
# skip and configure/1 is only honored before the suite starts.
#
# The reach decision is a standalone, non-linking TCP port probe: one
# short-lived :gen_tcp.connect with a bounded timeout, no process
# spawned, nothing linked to this loader, so a dead server cannot take
# the suite down. The Redis connectivity itself never happens at module
# definition; redis_test.exs opens its per-test connection in setup
# with sync_connect: false plus an explicit PING under try/rescue.
redis_url = System.get_env("KIWI_REDIS_URL", "redis://127.0.0.1:6379/15")
%URI{host: redis_host, port: redis_port} = URI.parse(redis_url)

redis_ready? =
  with {:ok, socket} <-
         :gen_tcp.connect(
           String.to_charlist(redis_host),
           redis_port || 6379,
           [:binary, active: false],
           250
         ) do
    :gen_tcp.close(socket)
    true
  else
    _ -> false
  end

unless redis_ready? do
  IO.puts(
    :stderr,
    "redis suite: no server reachable at #{redis_url} — excluding the :redis tests " <>
      "(environment condition, set KIWI_REDIS_URL to point elsewhere)"
  )

  ExUnit.configure(exclude: [redis: true])
end

ExUnit.start()
