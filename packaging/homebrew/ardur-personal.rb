class ArdurPersonal < Formula
  include Language::Python::Virtualenv

  desc "Local Ardur Personal Hub for browser, desktop, and CLI AI sessions"
  homepage "https://github.com/gnanirahulnutakki/ardur"
  # Development formula. Before publishing a stable tap formula, replace this
  # branch URL with a tagged tarball and run `brew update-python-resources` so
  # Python dependencies are declared as resource stanzas.
  url "https://github.com/gnanirahulnutakki/ardur.git", branch: "dev"
  version "0.1.0-dev"
  license "MIT"

  depends_on "python@3.13"

  def install
    cd "python" do
      virtualenv_install_with_resources
    end
    prefix.install "examples"
    prefix.install "docs"
  end

  service do
    run [opt_bin/"ardur", "hub"]
    keep_alive true
    log_path var/"log/ardur-personal.log"
    error_log_path var/"log/ardur-personal.err.log"
  end

  test do
    system bin/"ardur", "--version"
  end
end
