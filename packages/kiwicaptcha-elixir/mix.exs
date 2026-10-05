defmodule Kiwicaptcha.MixProject do
  use Mix.Project

  @version "1.0.0"

  def project do
    [
      app: :kiwicaptcha,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      test_paths: ["test"],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Zero hard dependencies: the verify path runs on the standard
  # library alone. The store backends and the web integration opt into
  # their packages as optional dependencies.
  defp deps do
    [
      {:redix, "~> 1.5", optional: true},
      {:plug, "~> 1.16", optional: true},
      {:exqlite, "~> 0.27", optional: true},
      {:jason, "~> 1.4", only: [:dev, :test], optional: true}
    ]
  end

  defp description do
    "KiwiCaptcha Elixir server SDK: local proof-of-work token verification " <>
      "over an injectable store, with a Plug integration, a typed outcomes " <>
      "client and a doctor task."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/kiwicaptcha/kiwicaptcha"},
      files: ~w(lib mix.exs README.md LICENSE)
    ]
  end
end
