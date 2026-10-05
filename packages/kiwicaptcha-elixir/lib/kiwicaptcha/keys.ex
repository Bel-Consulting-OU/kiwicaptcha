defmodule Kiwicaptcha.Keys do
  @moduledoc """
  Purpose key separation, byte identical to the PHP DerivedKeys and the
  Rust keys module. Every cryptographic purpose derives its own 32-byte
  key from the single master secret:

      prk         = hkdf extract (salt = deploy salt, ikm = master)
      k_challenge = hkdf expand(prk, "kiwi/v2/challenge-sign")
      k_ip_bind   = hkdf expand(prk, "kiwi/v2/ip-bind")
      k_result    = hkdf expand(prk, "kiwi/v2/result-token")
      k_server    = hkdf expand(prk, "kiwi/v2/server-state")

  A tenant id derives the purpose keys under the per-tenant root
  "kiwi/v2/tenant/" plus the tenant id, so tenants of one shared master
  secret cannot forge each other's material.
  """

  @deploy_salt "kiwicaptcha/deploy-salt/v1"
  @info_challenge_sign "kiwi/v2/challenge-sign"
  @info_ip_bind "kiwi/v2/ip-bind"
  @info_result_token "kiwi/v2/result-token"
  @info_server_state "kiwi/v2/server-state"
  @info_tenant_root_prefix "kiwi/v2/tenant/"

  @min_secret_bytes 32

  defstruct challenge_key: nil, ip_bind_key: nil, result_key: nil, server_state_key: nil

  @type t :: %__MODULE__{
          challenge_key: binary(),
          ip_bind_key: binary(),
          result_key: binary(),
          server_state_key: binary()
        }

  @spec deploy_salt :: String.t()
  def deploy_salt, do: @deploy_salt

  @spec min_secret_bytes :: non_neg_integer()
  def min_secret_bytes, do: @min_secret_bytes

  @doc "Expand one hkdf output of exactly 32 bytes."
  @spec hkdf32(binary(), String.t(), String.t()) :: binary()
  def hkdf32(ikm, info, salt) do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    # Standard HKDF-Expand: t(i) = hmac(prk, t(i-1) | info | i).
    block = :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
    binary_part(block, 0, 32)
  end

  @doc """
  Derive the purpose keys from the master secret. Raises when the
  secret is shorter than 32 bytes: a short secret must never derive
  usable keys.
  """
  @spec derived_keys(binary() | String.t(), String.t() | nil) :: t()
  def derived_keys(secret, tenant_id \\ nil)

  def derived_keys(secret, tenant_id) do
    master = IO.iodata_to_binary([secret])

    if byte_size(master) < @min_secret_bytes do
      raise Kiwicaptcha.RangeError,
            "the master secret must be at least #{@min_secret_bytes} bytes (got #{byte_size(master)})"
    end

    {ikm, salt} =
      if tenant_id do
        {hkdf32(master, @info_tenant_root_prefix <> tenant_id, @deploy_salt), ""}
      else
        {master, @deploy_salt}
      end

    %__MODULE__{
      challenge_key: hkdf32(ikm, @info_challenge_sign, salt),
      ip_bind_key: hkdf32(ikm, @info_ip_bind, salt),
      result_key: hkdf32(ikm, @info_result_token, salt),
      server_state_key: hkdf32(ikm, @info_server_state, salt)
    }
  end
end
