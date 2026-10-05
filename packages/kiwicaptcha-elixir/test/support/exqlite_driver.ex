defmodule Kiwicaptcha.Support.ExqliteDriver do
  @moduledoc """
  The test handle for the SQLite store: a thin delegate to the
  production `Kiwicaptcha.Stores.SqliteDriver.Exqlite` bridge, so the
  suites exercise the shipped serialization path, not a test double.
  `open/1` hands back the serialized handle so a suite can compose its
  own adapter options (the frozen clock), exactly the
  `open_handle/1` contract of the production module.
  """

  defdelegate available?, to: Kiwicaptcha.Stores.SqliteDriver.Exqlite

  def open(path), do: Kiwicaptcha.Stores.SqliteDriver.Exqlite.open_handle(path)

  defdelegate exec(handle, sql, params), to: Kiwicaptcha.Stores.SqliteDriver.Exqlite

  defdelegate close(handle), to: Kiwicaptcha.Stores.SqliteDriver.Exqlite
end
