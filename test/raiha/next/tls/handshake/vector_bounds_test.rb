require "raiha/next/test_helper"
require "raiha/next/tls"

# Boundary values generated from the table of vector bounds in RFC 9846's
# handshake messages: for each vector, its lower bound minus one, the lower
# bound, the upper bound and the upper bound plus one. Parsing accepts the
# two in range and raises RangeViolation for the others; encoding a value
# accepts and rejects the same lengths. A length that does not fit the
# length prefix, or would make the whole message longer than 2^24-1, cannot
# be built and is skipped.
class RaihaNextTLSHandshakeVectorBoundsTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Handshake = TLS::Handshake
  Extension = TLS::Extension
  REGISTRY = Extension::Registry::BUILTIN
  MAX_BODY = 0xffffff

  # A vector with an `n`-byte length prefix.
  def self.vec(n, bytes) = [bytes.bytesize].pack("N").byteslice(4 - n, n) + bytes.b

  def self.msg(type, body) = body.bytesize > MAX_BODY ? nil : [type].pack("C") + vec(3, body)

  # An extension block of exactly `length` bytes, made of one extension of a
  # type nobody knows; nil when `length` is 1 to 3.
  def self.block(length)
    return "".b if length.zero?
    return nil if length < 4
    [0x1234, length - 4].pack("nn") + "x".b * (length - 4)
  end

  def self.opaques(length)
    return [] if length.zero?
    return nil if length < 4
    [Extension::Opaque.new(type: 0x1234, data: "x".b * (length - 4))]
  end

  RANDOM = "\x11".b * 32
  VERSIONS_CH = "\x00\x2b\x00\x05\x04\x03\x04\x03\x03".b
  VERSIONS_SH = "\x00\x2b\x00\x02\x03\x04".b

  def self.ch_wire(sid: "", suites: "\x13\x01", compression: "\x00", extensions: VERSIONS_CH)
    return nil if extensions.nil?
    msg(1, "\x03\x03".b + RANDOM + vec(1, sid) + vec(2, suites) + vec(1, compression) + vec(2, extensions))
  end

  CH = Handshake::ClientHello.new(legacy_version: 0x0303, random: RANDOM, legacy_session_id: "".b,
    cipher_suites: [0x1301], legacy_compression_methods: [0],
    extensions: [Extension::SupportedVersions::CH.new(versions: [0x0304, 0x0303])])

  def self.sh_wire(sid: "", extensions: VERSIONS_SH)
    return nil if extensions.nil?
    msg(2, "\x03\x03".b + RANDOM + vec(1, sid) + "\x13\x01\x00".b + vec(2, extensions))
  end

  SH = Handshake::ServerHello.new(legacy_version: 0x0303, random: RANDOM, legacy_session_id_echo: "".b,
    cipher_suite: 0x1301, legacy_compression_method: 0,
    extensions: [Extension::SupportedVersions::SH.new(selected_version: 0x0304)])

  def self.certificate_wire(context: "", entries: nil, cert_data: "c", entry_extensions: "")
    return nil if entry_extensions.nil?
    entries ||= vec(3, cert_data) + vec(2, entry_extensions)
    msg(11, vec(1, context) + vec(3, entries))
  end

  def self.certificate(cert_data: "c".b, entry_extensions: [])
    entry = Handshake::CertificateEntry.new(cert_data:, extensions: entry_extensions)
    Handshake::Certificate.new(certificate_request_context: "".b, certificate_list: [entry])
  end

  def self.nst_wire(nonce: "", ticket: "t", extensions: "")
    return nil if extensions.nil?
    msg(4, "\x00\x00\x00\x1e\x00\x00\x00\x00".b + vec(1, nonce) + vec(2, ticket) + vec(2, extensions))
  end

  NST = Handshake::NewSessionTicket.new(ticket_lifetime: 30, ticket_age_add: 0, ticket_nonce: "".b, ticket: "t".b, extensions: [])

  CR = Handshake::CertificateRequest.new(certificate_request_context: "".b, extensions: [])

  # [message and field, min, max, length prefix, wire(n), value(n)]
  ROWS = [
    ["client_hello_legacy_session_id", 0, 32, 1,
      ->(n) { ch_wire(sid: "x" * n) }, ->(n) { CH.with(legacy_session_id: "x".b * n) }],
    ["client_hello_cipher_suites", 2, 0xfffe, 2,
      ->(n) { ch_wire(suites: "\x13" * n) }, ->(n) { n.even? ? CH.with(cipher_suites: [0x1301] * (n / 2)) : nil }],
    ["client_hello_legacy_compression_methods", 1, 0xff, 1,
      ->(n) { ch_wire(compression: "\x00" * n) }, ->(n) { CH.with(legacy_compression_methods: [0] * n) }],
    ["client_hello_extensions", 8, 0xffff, 2,
      ->(n) { ch_wire(extensions: block(n)) }, ->(n) { (list = opaques(n)) && CH.with(extensions: list) }],
    ["server_hello_legacy_session_id_echo", 0, 32, 1,
      ->(n) { sh_wire(sid: "x" * n) }, ->(n) { SH.with(legacy_session_id_echo: "x".b * n) }],
    ["server_hello_extensions", 6, 0xffff, 2,
      ->(n) { sh_wire(extensions: block(n)) }, ->(n) { (list = opaques(n)) && SH.with(extensions: list) }],
    # extension_data inside an EncryptedExtensions block, which must also
    # hold the 4-byte extension header.
    ["extension_extension_data", 0, 0xffff, 2,
      ->(n) { n > 0xffff - 4 ? nil : msg(8, vec(2, block(n + 4))) },
      ->(n) { n > 0xffff - 4 ? nil : Handshake::EncryptedExtensions.new(extensions: opaques(n + 4)) }],
    ["encrypted_extensions_extensions", 0, 0xffff, 2,
      ->(n) { (b = block(n)) && msg(8, vec(2, b)) }, ->(n) { (list = opaques(n)) && Handshake::EncryptedExtensions.new(extensions: list) }],
    ["certificate_request_certificate_request_context", 0, 0xff, 1,
      ->(n) { msg(13, vec(1, "x" * n) + vec(2, "")) }, ->(n) { CR.with(certificate_request_context: "x".b * n) }],
    ["certificate_request_extensions", 0, 0xffff, 2,
      ->(n) { (b = block(n)) && msg(13, vec(1, "") + vec(2, b)) }, ->(n) { (list = opaques(n)) && CR.with(extensions: list) }],
    ["certificate_certificate_request_context", 0, 0xff, 1,
      ->(n) { certificate_wire(context: "x" * n) }, ->(n) { certificate.with(certificate_request_context: "x".b * n) }],
    ["certificate_certificate_list", 0, 0xffffff, 3,
      ->(n) { n.zero? ? certificate_wire(entries: "") : (n < 6 ? nil : certificate_wire(cert_data: "c" * (n - 5))) },
      ->(n) { n.zero? ? certificate.with(certificate_list: []) : nil }],
    ["certificate_entry_cert_data", 1, 0xffffff, 3,
      ->(n) { certificate_wire(cert_data: "c" * n) }, ->(n) { n > 0xffff ? nil : certificate(cert_data: "c".b * n) }],
    ["certificate_entry_extensions", 0, 0xffff, 2,
      ->(n) { certificate_wire(entry_extensions: block(n)) },
      ->(n) { (list = opaques(n)) && certificate(entry_extensions: list) }],
    ["certificate_verify_signature", 0, 0xffff, 2,
      ->(n) { msg(15, "\x08\x04".b + vec(2, "s" * n)) },
      ->(n) { Handshake::CertificateVerify.new(algorithm: 0x0804, signature: "s".b * n) }],
    ["new_session_ticket_ticket_nonce", 0, 0xff, 1,
      ->(n) { nst_wire(nonce: "n" * n) }, ->(n) { NST.with(ticket_nonce: "n".b * n) }],
    ["new_session_ticket_ticket", 1, 0xffff, 2,
      ->(n) { nst_wire(ticket: "t" * n) }, ->(n) { NST.with(ticket: "t".b * n) }],
    ["new_session_ticket_extensions", 0, 0xffff, 2,
      ->(n) { nst_wire(extensions: block(n)) }, ->(n) { (list = opaques(n)) && NST.with(extensions: list) }]
  ].freeze

  ROWS.each do |name, min, max, prefix, wire, value|
    define_method(:"test_#{name}") do
      tried = 0
      [min - 1, min, max, max + 1].uniq.each do |n|
        next if n.negative? || n >= 256**prefix
        in_range = n.between?(min, max)

        if (bytes = wire.call(n))
          tried += 1
          if in_range
            assert_equal_bin bytes, Handshake.parse(bytes, registry: REGISTRY).encode
          else
            assert_raises(TLS::Codec::RangeViolation, "#{name} length #{n}") { Handshake.parse(bytes, registry: REGISTRY) }
          end
        end

        next unless (message = value.call(n))
        if in_range
          assert_equal message, Handshake.parse(message.encode, registry: REGISTRY)
        else
          assert_raises(TLS::Codec::EncodeError, "#{name} length #{n}") { message.encode }
        end
      end
      assert_operator tried, :>, 0
    end
  end
end
