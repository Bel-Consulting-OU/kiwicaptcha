using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;

namespace KiwiCaptcha;

/// <summary>
/// The narrow command surface the Redis store adapter binds to, so
/// tests and deployments can substitute any client with the same five
/// verbs. The shipped RESP2 client implements it over a plain socket.
/// </summary>
public interface IRedisClient
{
    /// <summary>Returns the string value, or null when the key is absent.</summary>
    string? Get(string key);

    /// <summary>Writes the value with a millisecond lifetime.</summary>
    void SetWithTtl(string key, string value, long ttlMillis);

    /// <summary>Returns the remaining lifetime in milliseconds.</summary>
    long Pttl(string key);

    /// <summary>Removes one key and reports whether it existed.</summary>
    bool Del(string key);

    /// <summary>Runs one script.</summary>
    object? Eval(string script, IReadOnlyList<string> keys, IReadOnlyList<string> args);

    /// <summary>Runs a cached script.</summary>
    object? EvalSha(string sha, IReadOnlyList<string> keys, IReadOnlyList<string> args);

    /// <summary>Caches one script and returns its hex digest.</summary>
    string ScriptLoad(string script);

    /// <summary>Sends one raw command and decodes the reply.</summary>
    object? Command(params string[] args);

    /// <summary>Probes the server.</summary>
    void Ping();

    /// <summary>Releases the connection.</summary>
    void Close();
}

/// <summary>
/// A minimal Redis client over the Redis wire protocol, implemented
/// on the .NET socket streams only. The client speaks RESP2, the
/// protocol the php and Python adapters run over, and implements the
/// narrow command surface the store adapter needs: get, set with a
/// lifetime, pttl, del, and script execution through eval, evalsha
/// and script load. One connection, serialized with a lock; the
/// adapter issues one request at a time.
/// </summary>
public sealed class RespClient : IRedisClient
{
    private Socket? _socket;
    private NetworkStream? _stream;

    /// <summary>A negative server reply.</summary>
    public sealed class RedisException : Exception
    {
        public string Message0 { get; }

        internal RedisException(string message)
            : base("kiwicaptcha: redis error: " + message)
        {
            Message0 = message;
        }

        /// <summary>Reports the noscript miss that triggers an eval reload.</summary>
        public bool IsNoScript() => Message0.ToLowerInvariant().Contains("noscript");
    }

    private RespClient(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
    }

    /// <summary>
    /// Builds the shipped client from a redis:// or rediss:// url. The
    /// rediss scheme is rejected with a clear error rather than
    /// silently downgrading: this client speaks the plaintext
    /// protocol only.
    /// </summary>
    public static RespClient Dial(string raw)
    {
        Uri? parsed = null;
        try
        {
            parsed = new Uri(raw);
        }
        catch (UriFormatException e)
        {
            throw new Exception("kiwicaptcha: bad redis url: " + e.Message, e);
        }
        if (string.Equals(parsed.Scheme, "rediss", StringComparison.OrdinalIgnoreCase))
        {
            throw new Exception(
                "kiwicaptcha: rediss:// needs a tls transport this client does not carry; " +
                "terminate tls at the redis proxy fronting the store");
        }
        var host = string.IsNullOrEmpty(parsed.Host) ? "127.0.0.1" : parsed.Host;
        var port = parsed.Port > 0 ? parsed.Port : 6379;
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var connect = socket.BeginConnect(host, port, null, null);
            if (!connect.AsyncWaitHandle.WaitOne(5000))
            {
                throw new Exception("kiwicaptcha: redis dial timed out");
            }
            socket.EndConnect(connect);
        }
        catch (Exception e)
        {
            try
            {
                socket.Close();
            }
            catch (Exception)
            {
                // The dial already failed.
            }
            if (e.Message.StartsWith("kiwicaptcha:", StringComparison.Ordinal))
            {
                throw;
            }
            throw new Exception("kiwicaptcha: redis dial failed: " + e.Message, e);
        }
        var client = new RespClient(socket);
        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            var colon = parsed.UserInfo.IndexOf(':');
            var password = colon >= 0 ? parsed.UserInfo[(colon + 1)..] : parsed.UserInfo;
            try
            {
                client.Command("AUTH", password);
            }
            catch (Exception e)
            {
                client.Close();
                throw new Exception("kiwicaptcha: redis auth failed: " + e.Message, e);
            }
        }
        return client;
    }

    /// <summary>Sends one command and decodes the reply.</summary>
    public object? Command(params string[] args)
    {
        lock (this)
        {
            if (_socket == null || _stream == null)
            {
                throw new Exception("kiwicaptcha: redis client is closed");
            }
            var sb = new StringBuilder();
            sb.Append('*').Append(args.Length).Append("\r\n");
            foreach (var arg in args)
            {
                var bytes = Encoding.UTF8.GetByteCount(arg);
                sb.Append('$').Append(bytes).Append("\r\n").Append(arg).Append("\r\n");
            }
            try
            {
                var payload = Encoding.UTF8.GetBytes(sb.ToString());
                _stream.Write(payload, 0, payload.Length);
                _stream.Flush();
                return ReadReply();
            }
            catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
            {
                throw new Exception("kiwicaptcha: redis write failed: " + e.Message, e);
            }
        }
    }

    private object? ReadReply()
    {
        var line = ReadLine();
        if (line.Length == 0)
        {
            throw new Exception("kiwicaptcha: redis sent an empty reply line");
        }
        var type = line[0];
        var body = line[1..];
        switch (type)
        {
            case '+':
                return body;
            case '-':
                throw new RedisException(body);
            case ':':
                return ParseLong(body);
            case '$':
            {
                var length = ParseLong(body);
                if (length < 0)
                {
                    return null;
                }
                var payload = ReadFull((int)length + 2);
                return Encoding.UTF8.GetString(payload, 0, (int)length);
            }
            case '*':
            {
                var count = ParseLong(body);
                if (count < 0)
                {
                    return null;
                }
                var outList = new List<object?>((int)count);
                for (var i = 0; i < count; i++)
                {
                    outList.Add(ReadReply());
                }
                return outList;
            }
            default:
                throw new Exception("kiwicaptcha: unknown redis reply type " + type);
        }
    }

    private static long ParseLong(string body)
    {
        if (!long.TryParse(body, out var value))
        {
            throw new Exception("kiwicaptcha: bad redis integer reply: " + body);
        }
        return value;
    }

    private string ReadLine()
    {
        var sb = new StringBuilder();
        try
        {
            var previous = -1;
            while (true)
            {
                var b = _stream!.ReadByte();
                if (b < 0)
                {
                    throw new IOException("connection closed");
                }
                if (previous == '\r' && b == '\n')
                {
                    return sb.ToString(0, sb.Length - 1);
                }
                sb.Append((char)b);
                previous = b;
            }
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
        {
            throw new Exception("kiwicaptcha: redis read failed: " + e.Message, e);
        }
    }

    private byte[] ReadFull(int n)
    {
        var buf = new byte[n];
        var total = 0;
        try
        {
            while (total < n)
            {
                var read = _stream!.Read(buf, total, n - total);
                if (read <= 0)
                {
                    throw new IOException("connection closed");
                }
                total += read;
            }
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
        {
            throw new Exception("kiwicaptcha: redis bulk read failed: " + e.Message, e);
        }
        return buf;
    }

    /// <summary>Returns the string value, or null when the key is absent.</summary>
    public string? Get(string key)
    {
        var reply = Command("GET", key);
        if (reply == null)
        {
            return null;
        }
        if (reply is not string value)
        {
            throw new Exception("kiwicaptcha: redis get returned a non string reply");
        }
        return value;
    }

    /// <summary>Writes the value with a millisecond lifetime.</summary>
    public void SetWithTtl(string key, string value, long ttlMillis) =>
        Command("SET", key, value, "PX", ttlMillis.ToString());

    /// <summary>Returns the remaining lifetime in milliseconds.</summary>
    public long Pttl(string key)
    {
        var reply = Command("PTTL", key);
        return reply is long value ? value : throw new Exception("kiwicaptcha: redis pttl returned a non integer reply");
    }

    /// <summary>Removes one key and reports whether it existed.</summary>
    public bool Del(string key)
    {
        var reply = Command("DEL", key);
        return reply is long value && value > 0;
    }

    public object? Eval(string script, IReadOnlyList<string> keys, IReadOnlyList<string> args)
    {
        var parts = new List<string>(3 + keys.Count + args.Count) { "EVAL", script, keys.Count.ToString() };
        parts.AddRange(keys);
        parts.AddRange(args);
        return Command(parts.ToArray());
    }

    public object? EvalSha(string sha, IReadOnlyList<string> keys, IReadOnlyList<string> args)
    {
        var parts = new List<string>(3 + keys.Count + args.Count) { "EVALSHA", sha, keys.Count.ToString() };
        parts.AddRange(keys);
        parts.AddRange(args);
        return Command(parts.ToArray());
    }

    public string ScriptLoad(string script)
    {
        var reply = Command("SCRIPT", "LOAD", script);
        return reply is string value
            ? value
            : throw new Exception("kiwicaptcha: script load returned a non string reply");
    }

    /// <summary>Probes the server.</summary>
    public void Ping() => Command("PING");

    /// <summary>Releases the connection.</summary>
    public void Close()
    {
        lock (this)
        {
            try
            {
                _stream?.Close();
                _socket?.Close();
            }
            catch (Exception)
            {
                // Closing is best-effort.
            }
            _stream = null;
            _socket = null;
        }
    }
}

/// <summary>
/// The Redis transition scripts, the same transitions the php
/// RedisStorage and the Go, Python and JVM adapters run, so every
/// adapter classifies and mutates the same stored envelopes with the
/// same Lua semantics.
/// </summary>
public static class LuaScripts
{
    /// <summary>The shared envelope inspection prelude.</summary>
    internal const string EnvelopePrelude = @"
-- Shared envelope inspection for the runtime transition scripts.
--
-- The runtime state is classified from the decoded top-level envelope,
-- never from a whole-document byte search: a corrupt or foreign value
-- that merely CONTAINS a nested ""state"":""pending"" (or consumed /
-- cancelled) string can never drive a transition. The mutations still
-- splice the raw JSON bytes (the record is never re-encoded through
-- cjson, so large integers never switch to scientific notation), and
-- every splice targets the top-level field span located by the scanner
-- below, so a nested occurrence can never be rewritten either. The
-- byte ceiling bounds the JSON parse before it happens.
local KIWI_ENVELOPE_MAX_BYTES = 131072
local KIWI_ENVELOPE_MAX_DEPTH = 32

local function kiwiNullish(x)
  return x == nil or x == cjson.null
end

local function kiwiIsSpace(c)
  return string.find(' \t\r\n', c, 1, true) ~= nil
end

local function kiwiSkipSpace(v, i, n)
  while i <= n do
    local c = string.sub(v, i, i)
    if not kiwiIsSpace(c) then break end
    i = i + 1
  end
  return i
end

local function kiwiSkipSpaceBack(v, j)
  while j >= 1 do
    local c = string.sub(v, j, j)
    if not kiwiIsSpace(c) then break end
    j = j - 1
  end
  return j
end

local function kiwiValueEnd(v, s, n)
  local c = string.sub(v, s, s)
  if c == '""' then
    local i = s + 1
    local esc = false
    while i <= n do
      local ci = string.sub(v, i, i)
      if esc then esc = false
      elseif ci == '\\' then esc = true
      elseif ci == '""' then return i end
      i = i + 1
    end
    return nil
  elseif c == '{' or c == '[' then
    local open = c
    local close = (c == '{') and '}' or ']'
    local depth = 0
    local i = s
    while i <= n do
      local ci = string.sub(v, i, i)
      if ci == '""' then
        i = i + 1
        local esc = false
        while i <= n do
          local cj = string.sub(v, i, i)
          if esc then esc = false
          elseif cj == '\\' then esc = true
          elseif cj == '""' then break end
          i = i + 1
        end
        if i > n then return nil end
      elseif ci == open then
        depth = depth + 1
      elseif ci == close then
        depth = depth - 1
        if depth == 0 then return i end
      end
      i = i + 1
    end
    return nil
  end
  local i = s
  while i <= n do
    local ci = string.sub(v, i, i)
    if ci == ',' or ci == '}' or ci == ']' or ci == ' ' or ci == '\t' or ci == '\r' or ci == '\n' then
      break
    end
    i = i + 1
  end
  if i == s then return nil end
  return i - 1
end

local function kiwiSkipString(v, i, n)
  i = i + 1
  while i <= n do
    local c = string.sub(v, i, i)
    if c == '\\' then
      i = i + 2
    elseif c == '""' then
      return i + 1
    else
      i = i + 1
    end
  end
  return nil
end

local kiwiUniqueScanValue
local kiwiUniqueScanObject
local kiwiUniqueScanArray

kiwiUniqueScanValue = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  if i > n then return nil end
  local c = string.sub(v, i, i)
  if c == '{' then
    return kiwiUniqueScanObject(v, i + 1, n, depth)
  end
  if c == '[' then
    return kiwiUniqueScanArray(v, i + 1, n, depth)
  end
  if c == '""' then
    return kiwiSkipString(v, i, n)
  end
  local start = i
  while i <= n do
    local c2 = string.sub(v, i, i)
    if c2 == ',' or c2 == '}' or c2 == ']' or kiwiIsSpace(c2) then break end
    i = i + 1
  end
  if i == start then return nil end
  return i
end

kiwiUniqueScanObject = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  local seen = {}
  i = kiwiSkipSpace(v, i, n)
  if i <= n and string.sub(v, i, i) == '}' then return i + 1 end
  while true do
    i = kiwiSkipSpace(v, i, n)
    if i > n or string.sub(v, i, i) ~= '""' then return nil end
    local keyEnd = kiwiSkipString(v, i, n)
    if keyEnd == nil then return nil end
    local token = string.sub(v, i, keyEnd - 1)
    local ok, key = pcall(cjson.decode, token)
    if not ok or type(key) ~= 'string' then return nil end
    if seen[key] ~= nil then return nil end
    seen[key] = true
    i = kiwiSkipSpace(v, keyEnd, n)
    if i > n or string.sub(v, i, i) ~= ':' then return nil end
    i = kiwiUniqueScanValue(v, kiwiSkipSpace(v, i + 1, n), n, depth + 1)
    if i == nil then return nil end
    i = kiwiSkipSpace(v, i, n)
    if i > n then return nil end
    local sep = string.sub(v, i, i)
    if sep == ',' then
      i = i + 1
    elseif sep == '}' then
      return i + 1
    else
      return nil
    end
  end
end

kiwiUniqueScanArray = function(v, i, n, depth)
  if depth > KIWI_ENVELOPE_MAX_DEPTH then return nil end
  i = kiwiSkipSpace(v, i, n)
  if i <= n and string.sub(v, i, i) == ']' then return i + 1 end
  while true do
    i = kiwiUniqueScanValue(v, i, n, depth + 1)
    if i == nil then return nil end
    i = kiwiSkipSpace(v, i, n)
    if i > n then return nil end
    local sep = string.sub(v, i, i)
    if sep == ',' then
      i = i + 1
    elseif sep == ']' then
      return i + 1
    else
      return nil
    end
  end
end

local function kiwiDocumentIsUnique(v)
  local n = #v
  if n == 0 or n > KIWI_ENVELOPE_MAX_BYTES then return false end
  local i = kiwiSkipSpace(v, 1, n)
  if i > n or string.sub(v, i, i) ~= '{' then return false end
  local endIndex = kiwiUniqueScanObject(v, i + 1, n, 0)
  if endIndex == nil then return false end
  return kiwiSkipSpace(v, endIndex, n) > n
end

local function kiwiTopLevelFields(v)
  local n = #v
  if n > KIWI_ENVELOPE_MAX_BYTES then return nil end
  if not kiwiDocumentIsUnique(v) then return nil end
  local i = 1
  i = kiwiSkipSpace(v, i, n)
  if string.sub(v, i, i) ~= '{' then return nil end
  i = i + 1
  local fields = {}
  while i <= n do
    local c = string.sub(v, i, i)
    if string.find(' \t\r\n,', c, 1, true) then
      i = i + 1
    elseif c == '}' then
      return fields
    elseif c == '""' then
      local j = i + 1
      local esc = false
      while j <= n do
        local cj = string.sub(v, j, j)
        if esc then esc = false
        elseif cj == '\\' then esc = true
        elseif cj == '""' then break end
        j = j + 1
      end
      if j > n then return nil end
      local name = string.sub(v, i + 1, j - 1)
      local nameOk, decodedName = pcall(cjson.decode, '""' .. name .. '""')
      if not nameOk or type(decodedName) ~= 'string' then return nil end
      if fields[decodedName] ~= nil then return nil end
      local p = j + 1
      p = kiwiSkipSpace(v, p, n)
      if string.sub(v, p, p) ~= ':' then return nil end
      local s = p + 1
      s = kiwiSkipSpace(v, s, n)
      local e = kiwiValueEnd(v, s, n)
      if e == nil then return nil end
      fields[decodedName] = {i, s, e}
      i = e + 1
    else
      return nil
    end
  end
  return nil
end

local function kiwiTopLevelField(v, key)
  local fields = kiwiTopLevelFields(v)
  if fields == nil then return nil end
  return fields[key]
end

local function kiwiReplaceTopLevel(v, key, literal)
  local span = kiwiTopLevelField(v, key)
  if span == nil then return nil end
  local head = string.sub(v, 1, span[2] - 1)
  local tail = string.sub(v, span[3] + 1)
  return head .. literal .. tail
end

local function kiwiRemoveTopLevel(v, key)
  local span = kiwiTopLevelField(v, key)
  if span == nil then return nil end
  local i = span[3] + 1
  i = kiwiSkipSpace(v, i, #v)
  if string.sub(v, i, i) == ',' then
    return string.sub(v, 1, span[1] - 1) .. string.sub(v, i + 1)
  end
  local j = span[1] - 1
  j = kiwiSkipSpaceBack(v, j)
  if string.sub(v, j, j) == ',' then
    return string.sub(v, 1, j - 1) .. string.sub(v, span[3] + 1)
  end
  return string.sub(v, 1, span[1] - 1) .. string.sub(v, span[3] + 1)
end

local function kiwiAppendTopLevel(v, literal)
  local n = #v
  local i = 1
  i = kiwiSkipSpace(v, i, n)
  if string.sub(v, i, i) ~= '{' then return nil end
  local depth = 0
  local last = nil
  local first = i
  while i <= n do
    local c = string.sub(v, i, i)
    if c == '""' then
      i = i + 1
      local esc = false
      while i <= n do
        local ci = string.sub(v, i, i)
        if esc then esc = false
        elseif ci == '\\' then esc = true
        elseif ci == '""' then break end
        i = i + 1
      end
      if i > n then return nil end
    elseif c == '{' or c == '[' then
      depth = depth + 1
    elseif c == '}' or c == ']' then
      depth = depth - 1
      if depth == 0 then last = i break end
    end
    i = i + 1
  end
  if last == nil then return nil end
  local p = last - 1
  p = kiwiSkipSpaceBack(v, p)
  if p == first then
    return string.sub(v, 1, last - 1) .. literal .. string.sub(v, last)
  end
  return string.sub(v, 1, last - 1) .. ',' .. literal .. string.sub(v, last)
end

local function kiwiDecodeEnvelope(v)
  if #v > KIWI_ENVELOPE_MAX_BYTES then return nil end
  local ok, decoded = pcall(cjson.decode, v)
  if not ok or type(decoded) ~= 'table' then return nil end
  return decoded
end
";

    /// <summary>The consume transition.</summary>
    public static readonly string ConsumeScript = EnvelopePrelude + @"
local v = redis.call(""GET"", KEYS[1])
if not v then
  return nil
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
if kiwiTopLevelFields(v) == nil then
  return nil
end
local state = decoded['state']
local consumedNow = 0
local consumedBefore = 0
local identitySpliced = 0
if state == 'consumed' then
  consumedBefore = 1
elseif state == 'pending' then
  if not kiwiNullish(decoded['consumed_result'])
    or not kiwiNullish(decoded['operation_identity'])
    or not kiwiNullish(decoded['resume_owner'])
    or not kiwiNullish(decoded['resume_until']) then
    return nil
  end
  local pttl = redis.call(""PTTL"", KEYS[1])
  if pttl < 0 then
    return false
  end
  if pttl < 1000 then pttl = 1000 end
  local updated = kiwiReplaceTopLevel(v, 'state', '""consumed""')
  if updated == nil then
    return nil
  end
  if ARGV[1] ~= '' then
    local withIdentity = kiwiReplaceTopLevel(updated, 'operation_identity', ARGV[1])
    if withIdentity ~= nil then
      updated = withIdentity
      identitySpliced = 1
    end
  end
  redis.call(""SET"", KEYS[1], updated, ""PX"", pttl)
  consumedNow = 1
  v = updated
else
  return nil
end
local resultJson = 'null'
local resultSpan = kiwiTopLevelField(v, 'consumed_result')
if resultSpan ~= nil then
  local value = string.sub(v, resultSpan[2], resultSpan[3])
  if value ~= 'null' then
    resultJson = value
  end
end
return {v, consumedNow, consumedBefore, resultJson, identitySpliced}
";

    /// <summary>The atomic cheap-failure cleanup.</summary>
    public static readonly string DeleteIfPendingScript = EnvelopePrelude + @"
local v = redis.call(""GET"", KEYS[1])
if not v then
  return {'missing'}
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return {'corrupt'}
end
if kiwiTopLevelFields(v) == nil then
  return {'corrupt'}
end
local state = decoded['state']
if state == 'consumed' then
  return {'consumed', v}
end
if state == 'cancelled' then
  return {'cancelled', v}
end
if state == 'pending' then
  redis.call(""DEL"", KEYS[1])
  return {'deleted-pending'}
end
return {'corrupt'}
";

    /// <summary>The terminal cancellation marker transition.</summary>
    public static readonly string CancelScript = EnvelopePrelude + @"
local v = redis.call(""GET"", KEYS[1])
if not v then
  return nil
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return nil
end
if kiwiTopLevelFields(v) == nil then
  return nil
end
local state = decoded['state']
if state == 'consumed' then
  return {'consumed'}
end
if state == 'cancelled' then
  return {'cancelled'}
end
if state ~= 'pending' then
  return nil
end
local pttl = redis.call(""PTTL"", KEYS[1])
if pttl < 0 then
  return false
end
if pttl < 1000 then pttl = 1000 end
local updated = kiwiReplaceTopLevel(v, 'state', '""cancelled""')
if updated == nil then
  return nil
end
redis.call(""SET"", KEYS[1], updated, ""PX"", pttl)
return {'cancelled-now'}
";

    /// <summary>The committed result write.</summary>
    public static readonly string CommitScript = EnvelopePrelude + @"
local v = redis.call(""GET"", KEYS[1])
if not v then
  return 0
end
local decoded = kiwiDecodeEnvelope(v)
if decoded == nil then
  return 0
end
if kiwiTopLevelFields(v) == nil then
  return 0
end
if decoded['state'] ~= 'consumed' then
  return 0
end
if not kiwiNullish(decoded['consumed_result']) then
  return 0
end
local claim = (ARGV[4] ~= nil) and (ARGV[4] ~= '')
if claim then
  if decoded['resume_owner'] ~= ARGV[4] then
    return 2
  end
  local untilVal = tonumber(decoded['resume_until'])
  local t = redis.call(""TIME"")
  local nowUs = tonumber(t[1]) * 1000000 + tonumber(t[2])
  if untilVal == nil or untilVal <= nowUs then
    return 2
  end
end
local pttl = redis.call(""PTTL"", KEYS[1])
if pttl < 0 then
  return 0
end
if pttl < 1000 then pttl = 1000 end
local encoded
if ARGV[5] ~= nil and ARGV[5] ~= '' then
  encoded = cjson.encode({
    valid = (ARGV[1] == '1'),
    binding = (ARGV[3] == ""0"") and cjson.null or ARGV[2],
    mac = ARGV[5]
  })
else
  encoded = cjson.encode({
    valid = (ARGV[1] == '1'),
    binding = (ARGV[3] == ""0"") and cjson.null or ARGV[2]
  })
end
local updated = kiwiReplaceTopLevel(v, 'consumed_result', encoded)
if updated == nil then
  return 0
end
if claim then
  local cleared = kiwiRemoveTopLevel(updated, 'resume_until')
  if cleared == nil then
    return 0
  end
  cleared = kiwiRemoveTopLevel(cleared, 'resume_owner')
  if cleared == nil then
    return 0
  end
  updated = cleared
end
redis.call(""SET"", KEYS[1], updated, ""PX"", pttl)
return 1
";
}

/// <summary>
/// Redis storage: the shared-backend store adapter, a port of the php
/// RedisStorage. The stored envelope is one json document per nonce
/// key: the flattened record fields plus the state, consumed_result
/// and operation_identity runtime markers. The consume, delete-if-
/// pending, cancel and commit transitions run the exact Lua scripts
/// of the php adapter, so envelopes written by either SDK are
/// interchangeable, byte for byte.
/// </summary>
public sealed class RedisStore : Store.IStoreAdapter, Store.IConsumedStateReader,
    Store.IRuntimeStateReader, Store.IAtomicDeleteIfPending, Store.IOperationIdentityAware,
    Store.IAuthenticatedResultCommit, Store.ICancellable, Store.IStorer
{
    private readonly IRedisClient _client;
    private readonly string _prefix;
    private readonly long _ttlMarginMillis;
    private readonly ConcurrentDictionary<string, string> _shaCache = new();

    /// <summary>Binds the adapter to a client.</summary>
    public RedisStore(IRedisClient client, string? prefix)
    {
        _client = client;
        _prefix = string.IsNullOrEmpty(prefix) ? Kiwi.EnvelopeDefaultPrefix : prefix;
        _ttlMarginMillis = Kiwi.RedisStorageTtl * 1000L;
    }

    private static Store.StorageUnavailableException Unavailable(Exception e) =>
        new(string.IsNullOrEmpty(e.Message) ? e.ToString() : e.Message);

    private object? Eval(string script, IReadOnlyList<string> keys, IReadOnlyList<string> args)
    {
        if (_shaCache.TryGetValue(script, out var sha))
        {
            try
            {
                return _client.EvalSha(sha, keys, args);
            }
            catch (RespClient.RedisException e)
            {
                if (!e.IsNoScript())
                {
                    throw Unavailable(e);
                }
            }
            catch (Exception e)
            {
                throw Unavailable(e);
            }
        }
        string loaded;
        try
        {
            loaded = _client.ScriptLoad(script);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (!string.IsNullOrEmpty(loaded))
        {
            _shaCache[script] = loaded;
        }
        try
        {
            return _client.Eval(script, keys, args);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
    }

    private sealed class EnvelopeDoc
    {
        internal ChallengeRecord? Record;
        internal string State = "";
        internal string Identity = "";
        internal Store.ConsumedResult? Result;
    }

    private static EnvelopeDoc DecodeEnvelope(string? raw)
    {
        var doc = new EnvelopeDoc();
        if (string.IsNullOrEmpty(raw) || raw.Length > Kiwi.EnvelopeMaxBytes)
        {
            return doc;
        }
        object? value;
        try
        {
            value = StrictJson.Decode(Encoding.UTF8.GetBytes(raw));
        }
        catch (ArgumentException)
        {
            return doc;
        }
        if (value is not Dictionary<string, object?> data)
        {
            return doc;
        }
        if (data.TryGetValue("state", out var state) && state is string stateText)
        {
            doc.State = stateText;
        }
        if (data.TryGetValue("operation_identity", out var identity) && identity is string identityText)
        {
            doc.Identity = identityText;
        }
        if (data.TryGetValue("consumed_result", out var rawResult) && rawResult is Dictionary<string, object?> resultMap)
        {
            try
            {
                doc.Result = ConsumedResultFromMap(resultMap);
            }
            catch (ArgumentException)
            {
                // An unusable result payload is not a record failure.
            }
        }
        var recordData = new Dictionary<string, object?>();
        foreach (var (key, item) in data)
        {
            if (key is "state" or "consumed_result" or "operation_identity" or "resume_owner" or "resume_until")
            {
                continue;
            }
            recordData[key] = item;
        }
        try
        {
            doc.Record = ChallengeRecord.FromMap(recordData);
        }
        catch (Exception)
        {
            return doc;
        }
        return doc;
    }

    private static Store.ConsumedResult ConsumedResultFromMap(Dictionary<string, object?> data)
    {
        foreach (var key in data.Keys)
        {
            if (key is not ("valid" or "binding" or "mac"))
            {
                throw new ArgumentException("consumed_result carries unsupported keys");
            }
        }
        bool valid;
        if (data.TryGetValue("valid", out var rawValid))
        {
            valid = rawValid switch
            {
                bool b => b,
                JsonNumber n => n.Raw == "1",
                _ => throw new ArgumentException("consumed_result.valid must be a boolean"),
            };
        }
        else
        {
            valid = false;
        }
        string binding = "";
        if (data.TryGetValue("binding", out var rawBinding))
        {
            binding = rawBinding switch
            {
                string s => s,
                null => "",
                _ => throw new ArgumentException("consumed_result.binding must be a string or null"),
            };
        }
        string mac = "";
        if (data.TryGetValue("mac", out var rawMac) && rawMac != null)
        {
            if (rawMac is not string macText)
            {
                throw new ArgumentException("consumed_result.mac must be a string or null");
            }
            if (!SolutionToken.IsHexN(macText, 64))
            {
                throw new ArgumentException("consumed_result.mac must be 64 lowercase hex characters");
            }
            mac = macText;
        }
        return new Store.ConsumedResult(valid, binding, mac);
    }

    /// <summary>Persists one pending record with the signed remainder plus the margin.</summary>
    public void StoreRecord(ChallengeRecord record)
    {
        var envelope = record.ToWireMap();
        envelope["state"] = "pending";
        envelope["consumed_result"] = null;
        envelope["operation_identity"] = null;
        var encoded = WireJson.EncodeEnvelope(envelope);
        var ttlSeconds = record.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var ttlMillis = ttlSeconds * 1000 + _ttlMarginMillis;
        if (ttlMillis < 1000)
        {
            ttlMillis = 1000;
        }
        try
        {
            _client.SetWithTtl(_prefix + record.Nonce, encoded, ttlMillis);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
    }

    /// <summary>Reads the record from the envelope.</summary>
    public ChallengeRecord? Find(string nonce)
    {
        string? raw;
        try
        {
            raw = _client.Get(_prefix + nonce);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (raw == null)
        {
            return null;
        }
        return DecodeEnvelope(raw).Record;
    }

    private Store.ConsumedRecord? Consume(string nonce, string identityJson)
    {
        object? reply;
        try
        {
            reply = Eval(LuaScripts.ConsumeScript,
                new[] { _prefix + nonce }, new[] { identityJson ?? "" });
        }
        catch (Store.StorageUnavailableException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (reply is not List<object?> items || items.Count < 3 || items[0] == null)
        {
            return null;
        }
        if (items[0] is not string payload)
        {
            return null;
        }
        var doc = DecodeEnvelope(payload);
        if (doc.Record == null)
        {
            return null;
        }
        return new Store.ConsumedRecord(doc.Record,
            ReplyInt(items[1]) == 1,
            ReplyInt(items[2]) == 1,
            doc.Result, doc.Identity);
    }

    /// <summary>Runs the fused one-shot transition.</summary>
    public Store.ConsumedRecord? Consume(string nonce) => Consume(nonce, "");

    /// <summary>
    /// Runs the fused transition and records the validated identity
    /// atomically with the flip.
    /// </summary>
    public Store.ConsumedRecord? ConsumeWithOperationIdentity(string nonce, string? operationIdentity)
    {
        var identity = Store.ValidateOperationIdentity(operationIdentity);
        var identityJson = identity.Length == 0 ? "" : WireJson.EncodeJsonString(identity);
        return Consume(nonce, identityJson);
    }

    /// <summary>Reads the retained consumed envelope.</summary>
    public Store.ConsumedRecord? ConsumedState(string nonce)
    {
        string? raw;
        try
        {
            raw = _client.Get(_prefix + nonce);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (raw == null)
        {
            return null;
        }
        var doc = DecodeEnvelope(raw);
        if (doc.Record == null || doc.State != "consumed")
        {
            return null;
        }
        return new Store.ConsumedRecord(doc.Record, false, true, doc.Result, doc.Identity);
    }

    /// <summary>Runs the fused atomic cleanup.</summary>
    public Store.DeleteIfPendingResult DeleteIfPending(string nonce)
    {
        object? reply;
        try
        {
            reply = Eval(LuaScripts.DeleteIfPendingScript, new[] { _prefix + nonce }, Array.Empty<string>());
        }
        catch (Store.StorageUnavailableException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (reply is not List<object?> items || items.Count == 0)
        {
            throw new Store.StorageUnavailableException("delete-if-pending returned an unexpected reply");
        }
        var status = items[0] as string ?? "";
        if (Store.DeleteStatusConsumed == status)
        {
            if (items.Count < 2)
            {
                throw new Store.StorageUnavailableException("delete-if-pending lost the consumed envelope");
            }
            var payload = items[1] as string ?? "";
            var doc = DecodeEnvelope(payload);
            if (doc.Record == null)
            {
                throw new Store.StorageUnavailableException("delete-if-pending returned an undecodable envelope");
            }
            return new Store.DeleteIfPendingResult(Store.DeleteStatusConsumed,
                new Store.ConsumedRecord(doc.Record, false, true, doc.Result, doc.Identity));
        }
        if (status.Length == 0)
        {
            status = Store.DeleteStatusCorrupt;
        }
        return new Store.DeleteIfPendingResult(status, null);
    }

    /// <summary>Reads the terminal-aware snapshot.</summary>
    public Store.ChallengeRuntimeState RuntimeState(string nonce)
    {
        string? raw;
        try
        {
            raw = _client.Get(_prefix + nonce);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (raw == null)
        {
            return Store.ChallengeRuntimeState.Missing();
        }
        var doc = DecodeEnvelope(raw);
        if (doc.Record == null)
        {
            return Store.ChallengeRuntimeState.Missing();
        }
        return doc.State switch
        {
            "cancelled" => new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Cancelled, doc.Record, null),
            "consumed" => new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Consumed, doc.Record,
                new Store.ConsumedRecord(doc.Record, false, true, doc.Result, doc.Identity)),
            "pending" => new Store.ChallengeRuntimeState(Store.RuntimeStateKind.Pending, doc.Record, null),
            _ => Store.ChallengeRuntimeState.Missing(),
        };
    }

    /// <summary>Flips the terminal cancellation marker through the fused script.</summary>
    public Store.CancellationResult? Cancel(string nonce)
    {
        object? reply;
        try
        {
            reply = Eval(LuaScripts.CancelScript, new[] { _prefix + nonce }, Array.Empty<string>());
        }
        catch (Store.StorageUnavailableException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        if (reply is not List<object?> items || items.Count == 0)
        {
            return null;
        }
        var status = items[0] as string ?? "";
        if (status.Length == 0)
        {
            return null;
        }
        return new Store.CancellationResult(status);
    }

    /// <summary>Removes one key.</summary>
    public bool Delete(string nonce)
    {
        try
        {
            return _client.Del(_prefix + nonce);
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
    }

    /// <summary>Commits the deterministic outcome without a mac.</summary>
    public bool CommitResult(string nonce, bool valid, string binding) =>
        CommitAuthenticatedResult(nonce, new Store.ConsumedResult(valid, binding, ""));

    /// <summary>
    /// Commits the outcome with its server-state mac through the
    /// fused script. The write preserves the key's remaining lifetime
    /// and refuses a key without one.
    /// </summary>
    public bool CommitAuthenticatedResult(string nonce, Store.ConsumedResult result)
    {
        var args = new List<string>
        {
            BoolArg(result.Valid),
            result.Binding,
            BoolArg(result.Binding.Length > 0),
            "",
            result.Mac,
        };
        object? reply;
        try
        {
            reply = Eval(LuaScripts.CommitScript, new[] { _prefix + nonce }, args);
        }
        catch (Store.StorageUnavailableException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw Unavailable(e);
        }
        return ReplyInt(reply) == 1;
    }

    private static long ReplyInt(object? reply) => reply is long value ? value : 0;

    private static string BoolArg(bool value) => value ? "1" : "0";
}
