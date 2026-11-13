require "test_helper"
require "raiha/tls"

class RaihaTLSServerNameTest < Minitest::Test
  ServerName = Raiha::TLS::ServerName

  def test_client_normalizes_dns_names
    assert_equal ["example.com", "example.com"], ServerName.for_client("Example.COM.")
    assert_equal ["xn--bcher-kva.example", "xn--bcher-kva.example"], ServerName.for_client("xn--bcher-kva.example")
  end

  # RFC 6066: an address literal is never sent as SNI, but the certificate
  # is still checked against it.
  def test_client_sends_no_sni_for_an_address
    assert_equal [nil, "192.0.2.1"], ServerName.for_client("192.0.2.1")
    assert_equal [nil, "[2001:db8::1]"], ServerName.for_client("[2001:db8::1]")
  end

  def test_client_rejects_names_that_are_not_ascii_host_names
    ["bücher.example", "a b.example", "", "a..b", "-" * 64 + ".example", ("a." * 127) + "aa"].each do |name|
      assert_raises(ArgumentError, name) { ServerName.for_client(name) }
    end
  end

  def test_server_ignores_what_it_cannot_use
    assert_equal ["example.com", nil], ServerName.for_server("EXAMPLE.com.")
    assert_equal [nil, :ip_literal], ServerName.for_server("192.0.2.1")
    assert_equal [nil, :invalid_syntax], ServerName.for_server("bad_name.example")
    assert_equal [nil, :invalid_syntax], ServerName.for_server("bücher".b)
    assert_equal [nil, :invalid_syntax], ServerName.for_server("a" * 64)
  end
end
