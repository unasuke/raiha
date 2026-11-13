require "test_helper"
require "support/test_pki"
require "raiha/tls"

class RaihaNextTLSVerifierTest < Minitest::Test
  TLS = Raiha::TLS
  Verifier = TLS::Verifier
  PKI = NextTestPKI
  NOW = PKI::NOW

  def ca = @ca ||= PKI.ca

  def verifier(verify_flags: 0) = Verifier::Default.new(store: Verifier::Default.store([ca.der]), verify_flags:)

  def verify(leaf, server_name: "localhost", now: NOW, purpose: :server, chain: [leaf.certificate])
    verifier.verify(chain:, server_name:, now:, purpose:)
  end

  def test_accepts_a_chain_to_the_anchor_for_the_name
    leaf = PKI.leaf(ca)
    result = verify(leaf)
    assert result.ok
    assert_nil result.reason
    assert_equal [leaf.der, ca.der], result.verified_chain.map(&:to_der)
  end

  def test_reasons_are_alerts
    assert_equal :unknown_ca, verify(PKI.leaf(PKI.ca(name: "Other CA", key: PKI.key(:other_ca)))).reason
    assert_equal :certificate_expired, verify(PKI.leaf(ca), now: NOW + 86400 * 31).reason
    assert_equal :bad_certificate, verify(PKI.leaf(ca), now: NOW - 86400 * 2).reason
    assert_equal :bad_certificate, verify(PKI.leaf(ca), chain: []).reason
    assert_equal :unsupported_certificate, verify(PKI.leaf(ca, purpose: "clientAuth")).reason
  end

  def test_name_mismatch_is_bad_certificate
    result = verify(PKI.leaf(ca), server_name: "example.com")
    refute result.ok
    assert_equal :bad_certificate, result.reason
    assert_empty result.verified_chain
  end

  def test_a_client_certificate_has_no_name_to_match
    assert verify(PKI.leaf(ca, names: [], purpose: "clientAuth"), server_name: nil, purpose: :client).ok
    refute verify(PKI.leaf(ca, names: [], purpose: "clientAuth"), server_name: nil, purpose: :server).ok
  end

  # RFC 9525 dropped the fallback to the subject's commonName.
  def test_common_name_is_never_matched
    refute verify(PKI.leaf(ca, names: [], common_name: "localhost")).ok
  end

  def test_revocation_is_checked_only_when_asked
    leaf = PKI.leaf(ca, serial: 7)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = ca.certificate.subject
    crl.last_update = NOW - 3600
    crl.next_update = NOW + 3600
    revoked = OpenSSL::X509::Revoked.new
    revoked.serial = 7
    revoked.time = NOW - 60
    crl.add_revoked(revoked)
    crl.sign(ca.key, "SHA256")
    store = Verifier::Default.store([ca.der])
    store.add_crl(crl)

    assert Verifier::Default.new(store:).verify(chain: [leaf.certificate], server_name: "localhost", now: NOW, purpose: :server).ok
    checked = Verifier::Default.new(store:, verify_flags: OpenSSL::X509::V_FLAG_CRL_CHECK)
    result = checked.verify(chain: [leaf.certificate], server_name: "localhost", now: NOW, purpose: :server)
    assert_equal :certificate_revoked, result.reason
  end

  def test_store_rejects_a_trust_anchor_that_is_not_der
    assert_raises(ArgumentError) { Verifier::Default.store(["not a certificate".b]) }
  end

  def test_resumption_policy
    assert_equal "default;verify_flags=0", verifier.resumption_policy
    refute_equal verifier.resumption_policy, verifier(verify_flags: OpenSSL::X509::V_FLAG_X509_STRICT).resumption_policy
    assert_equal "none", Verifier::None.new.resumption_policy
    # Revocation, which a resumption could not check again, has none.
    assert_nil verifier(verify_flags: OpenSSL::X509::V_FLAG_CRL_CHECK).resumption_policy
    assert_nil verifier(verify_flags: OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL).resumption_policy
  end

  def test_none_accepts_anything
    leaf = PKI.leaf(PKI.ca(name: "Other CA", key: PKI.key(:other_ca)))
    result = Verifier::None.new.verify(chain: [leaf.certificate], server_name: "example.com", now: NOW, purpose: :server)
    assert result.ok
    assert_equal [leaf.certificate], result.verified_chain
  end
end

class RaihaNextTLSVerifierHostNameTest < Minitest::Test
  HostName = Raiha::TLS::Verifier::HostName
  PKI = NextTestPKI

  def match?(names, name) = HostName.match?(PKI.leaf(PKI.ca, names:).certificate, name)

  def test_dns_names
    assert match?(["DNS:example.com"], "example.com")
    assert match?(["DNS:Example.COM."], "example.com")
    refute match?(["DNS:example.com"], "www.example.com")
    assert match?(["DNS:other.test", "DNS:example.com"], "example.com")
  end

  # A wildcard is valid only as the whole leftmost label and matches exactly
  # one label.
  def test_wildcards
    assert match?(["DNS:*.example.com"], "www.example.com")
    refute match?(["DNS:*.example.com"], "example.com")
    refute match?(["DNS:*.example.com"], "a.b.example.com")
    refute match?(["DNS:w*.example.com"], "www.example.com")
    refute match?(["DNS:www.*.com"], "www.example.com")
    refute match?(["DNS:*.*.example.com"], "a.b.example.com")
  end

  def test_ip_addresses
    assert match?(["IP:192.0.2.1"], "192.0.2.1")
    refute match?(["IP:192.0.2.1"], "192.0.2.2")
    assert match?(["IP:2001:db8::1"], "2001:db8::1")
    assert match?(["IP:2001:db8::1"], "[2001:db8::1]")
    # An address is never matched against a dNSName.
    refute match?(["DNS:192.0.2.1"], "192.0.2.1")
  end
end
