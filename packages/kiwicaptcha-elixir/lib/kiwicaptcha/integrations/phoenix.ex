defmodule Kiwicaptcha.PhoenixComponent do
  @moduledoc """
  The Phoenix functional component helpers, heex-compatible through
  raw `{:safe, iodata}` tuples. No Phoenix package is required to
  compile or use the core; the helpers are pure string builders a
  template or a controller can embed.

      <form method="post" action="/login" {Kiwicaptcha.PhoenixComponent.form_attributes("login")}>
        <%= raw Kiwicaptcha.PhoenixComponent.form_field("login") %>
      </form>
  """

  @default_script_path "/kiwi.js"
  @default_token_field "kiwi__token"

  defstruct []

  @doc """
  The hidden token input plus the driver script tag, carrying the scope
  on the input itself so one helper call is the whole Tier A drop-in:
  the driver script reads the scope, solves the challenge and fills
  the token before submit.
  """
  @spec form_field(String.t(), keyword()) :: {:safe, iodata()}
  def form_field(scope, opts \\ []) do
    token_field = Keyword.get(opts, :token_field, @default_token_field)
    script = Keyword.get(opts, :script, @default_script_path)

    {:safe,
     [
       ~s(<script src="),
       script,
       ~s(" defer></script>),
       ~s(\n<input type="hidden" name="),
       token_field,
       ~s(" data-kiwi="),
       scope,
       ~s(">)
     ]}
  end

  @doc "The scope declaration fragment for a form open tag."
  @spec form_attributes(String.t()) :: {:safe, iodata()}
  def form_attributes(scope) do
    {:safe, [~s(data-kiwi="), scope, ~s(")]}
  end
end
