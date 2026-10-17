if Code.ensure_loaded?(Plug) do
  defmodule Kiwicaptcha.Plug do
    @moduledoc """
    The Plug router integration: collects the configured token field
    under the shared authority rule, verifies the token locally, and
    answers 422 with a JSON error body on a definitive denial. A retry
    decision answers 503. A verified request assigns `:kiwi` on the
    conn, so the decision handle, the price rung and the binding ride
    along into the downstream actions.

        forward "/kiwi-protected", to: Kiwicaptcha.Plug,
          verify: {MyStore, :options, []}

    The `:verify` option is an MFA tuple resolved per request into the
    options map, or a zero-arity fun. `:token_field`, `:failure_status`
    and `:failure_redirect` mirror the other SDK integrations. The plug
    never raises: a storage outage is a 503 with the typed
    storage_unavailable code, fail closed.

    `:trusted_proxies` is the trusted-proxy CIDR list. The default
    (option absent) leaves the client-IP choice to the host options;
    when configured (an empty list included) a resolved options map
    without an explicit `:client_ip` gains the canonical IP from
    `Kiwicaptcha.ClientIp`: the socket peer, or a forwarded entry when
    a trusted hop justifies one. Plug.Conn merges repeated header
    lines, so the merged chain is what the resolver walks.
    """

    @behaviour Plug
    import Plug.Conn

    @default_token_field "kiwi__token"
    @default_failure_status 422

    @impl Plug
    def init(opts) do
      %{
        verify: Keyword.fetch!(opts, :verify),
        token_field: Keyword.get(opts, :token_field, @default_token_field),
        failure_status: Keyword.get(opts, :failure_status, @default_failure_status),
        failure_redirect: Keyword.get(opts, :failure_redirect),
        trusted_proxies: Keyword.get(opts, :trusted_proxies)
      }
    end

    @impl Plug
    def call(conn, config) do
      {conn, raw_token, failure} = read_token(conn, config.token_field)

      unless is_nil(failure) do
        detail =
          if failure == :token_source_conflict do
            "the request carries conflicting token sources"
          else
            "the #{config.token_field} field is missing"
          end

        fail(conn, config, failure, detail)
      else
        options = config.verify |> resolve_options(conn) |> apply_resolved_client_ip(conn, config)
        result = Kiwicaptcha.verify(raw_token, options)

        if result.ok do
          assign(conn, :kiwi, result)
        else
          code = if result.code == :"", do: :invalid, else: result.code
          status = if result.disposition == :retry, do: 503, else: nil
          fail(conn, config, code, result.detail || "verification failed", status)
        end
      end
    end

    defp read_token(conn, field) do
      header_values = conn |> get_req_header("x-kiwi-token") |> Kiwicaptcha.TokenSource.split_header()
      query_values =
        conn.query_string
        |> Kiwicaptcha.TokenSource.form_pairs()
        |> Kiwicaptcha.TokenSource.values_for(field)

      {form_values, conn} = raw_form_values(conn, field)

      {token, failure} =
        Kiwicaptcha.TokenSource.resolve_values(header_values, form_values, query_values)

      if is_nil(token) and failure == :malformed_token do
        # A host parser may have consumed the body before this plug ran.
        # The settled params still carries the field value.
        from_params =
          case fetch_params(conn) do
            %{^field => value} when is_binary(value) and value != "" -> [value]
            %{^field => values} when is_list(values) -> Enum.filter(values, &is_binary/1)
            _ -> []
          end

        {token, failure} =
          Kiwicaptcha.TokenSource.resolve_values(header_values, from_params, [])

        {conn, token, failure}
      else
        {conn, token, failure}
      end
    end

    defp raw_form_values(conn, field) do
      content_type = conn |> get_req_header("content-type") |> List.first() |> to_string()

      if String.contains?(content_type, "application/x-www-form-urlencoded") do
        case conn.body_params do
          %Plug.Conn.Unfetched{} ->
            case Plug.Conn.read_body(conn) do
              {:ok, body, conn} ->
                {Kiwicaptcha.TokenSource.form_pairs(body)
                 |> Kiwicaptcha.TokenSource.values_for(field), conn}

              {:more, body, conn} ->
                {Kiwicaptcha.TokenSource.form_pairs(body)
                 |> Kiwicaptcha.TokenSource.values_for(field), conn}

              {:error, _} ->
                {[], conn}
            end

          params when is_map(params) ->
            {param_values(params, field), conn}
        end
      else
        {[], conn}
      end
    end

    defp param_values(params, field) do
      case params do
        %{^field => value} when is_binary(value) and value != "" -> [value]
        %{^field => values} when is_list(values) -> Enum.filter(values, &is_binary/1)
        _ -> []
      end
    end

    defp fetch_params(conn) do
      case conn.params do
        %Plug.Conn.Unfetched{} -> %{}
        params -> params
      end
    rescue
      _ -> %{}
    end

    defp resolve_options({module, fun, args}, _conn), do: apply(module, fun, args)
    defp resolve_options(fun, conn) when is_function(fun, 1), do: fun.(conn)
    defp resolve_options(options, _conn) when is_map(options), do: options

    defp apply_resolved_client_ip(options, conn, config) do
      if is_map(options) and config.trusted_proxies != nil and is_nil(options[:client_ip]) do
        Map.put(options, :client_ip, client_ip(conn, config.trusted_proxies))
      else
        options
      end
    end

    defp client_ip(conn, trusted_proxies) do
      peer = peer_text(conn)

      Kiwicaptcha.ClientIp.resolve(
        peer: peer,
        xff: get_req_header(conn, "x-forwarded-for"),
        real_ip: conn |> get_req_header("x-real-ip") |> List.first(),
        trusted_proxies: trusted_proxies
      )
    end

    # The socket peer text: Plug reports the :remote_ip field as a
    # tuple, rendered through :inet.ntoa.
    defp peer_text(conn) do
      case conn.remote_ip do
        {a, b, c, d} -> :inet.ntoa({a, b, c, d}) |> to_string()
        {a, b, c, d, e, f, g, h} -> :inet.ntoa({a, b, c, d, e, f, g, h}) |> to_string()
        other -> to_string(other)
      end
    end

    defp fail(conn, config, code, detail, status \\ nil) do
      if config.failure_redirect && is_nil(status) do
        conn
        |> put_resp_header("location", config.failure_redirect)
        |> send_resp(303, "")
        |> halt()
      else
        body = encode_json(%{"error" => %{"code" => to_string(code), "detail" => detail}})

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(status || config.failure_status, body)
        |> halt()
      end
    end

    defp encode_json(value), do: Kiwicaptcha.Json.encode!(value)
  end
end
