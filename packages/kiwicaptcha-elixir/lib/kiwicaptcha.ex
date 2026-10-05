defmodule Kiwicaptcha do
  @moduledoc """
  KiwiCaptcha Elixir server SDK.

  Verifies client-submitted proof-of-work solution tokens, byte for
  byte compatible with the PHP and Rust cores. Verification is pure
  local: the signature, the message authentication codes and the store
  adapter are the only inputs, and no call ever reaches a network
  service.

  The public surface mirrors the shared server SDK contract:

  * `Kiwicaptcha.verify/2` resolves to a map with `:ok`,
    `:disposition`, `:decision_handle` and `:price`.
  * `Kiwicaptcha.Plug` is the drop-in router integration; the
    Phoenix component helpers render the Tier A markup.
  * `Kiwicaptcha.Outcomes` is the versioned outcomes mapping and
    client.
  * `Kiwicaptcha.Stores.Memory`, `Kiwicaptcha.Stores.Redis` and
    `Kiwicaptcha.Stores.Sqlite` implement one injectable storage
    behaviour.
  * `mix kiwicaptcha.doctor` validates a deployment.
  """

  @doc """
  Verify a client-submitted solution token: the one-call entry of the
  shared contract. The options map merges over `Verify.default_options/0`;
  `:storage` and `:secret_key` are required.
  """
  @spec verify(String.t(), map()) :: Kiwicaptcha.Verify.result()
  def verify(raw_token, options) when is_binary(raw_token) and is_map(options) do
    Kiwicaptcha.Verify.verify(raw_token, options)
  end
end
