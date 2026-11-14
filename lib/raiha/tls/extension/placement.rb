# frozen_string_literal: true

module Raiha::TLS
  module Extension
    # Which extension may appear in which message, and the class that parses
    # it there: RFC 9846's table of extensions and messages, plus the
    # extensions from other RFCs this implementation knows. A context is the
    # message the extension block belongs to; a HelloRetryRequest and a
    # CertificateEntry are contexts of their own.
    #
    # A type listed here but not for the context is `illegal_parameter`. A
    # type not listed at all is unknown and kept as an Opaque, because RFC 9846
    # requires unknown extensions to be ignored.
    #
    # status_request_v2 (17) is left out on purpose: RFC 6961 says a client
    # must tolerate it but not act on it, which is what ignoring it does.
    PLACEMENT = Ractor.make_shareable({
      ServerName::TYPE => { client_hello: ServerName::CH, encrypted_extensions: ServerName::EE },
      # status_request. Not sent in v1, so the certificate status is not parsed.
      5 => {
        client_hello: Opaque::Parser.new(type: 5),
        certificate_request: Opaque::Parser.new(type: 5),
        certificate_entry: Opaque::Parser.new(type: 5)
      },
      SupportedGroups::TYPE => { client_hello: SupportedGroups, encrypted_extensions: SupportedGroups },
      SignatureAlgorithms::TYPE => { client_hello: SignatureAlgorithms, certificate_request: SignatureAlgorithms },
      Alpn::TYPE => { client_hello: Alpn, encrypted_extensions: Alpn },
      # signed_certificate_timestamp. Not verified, so kept raw.
      18 => {
        client_hello: Opaque::Parser.new(type: 18),
        certificate_request: Opaque::Parser.new(type: 18),
        certificate_entry: Opaque::Parser.new(type: 18)
      },
      CompressCertificate::TYPE => { client_hello: CompressCertificate, certificate_request: CompressCertificate },
      RecordSizeLimit::TYPE => { client_hello: RecordSizeLimit, encrypted_extensions: RecordSizeLimit },
      PreSharedKey::TYPE => { client_hello: PreSharedKey::CH, server_hello: PreSharedKey::SH },
      EarlyData::TYPE => {
        client_hello: EarlyData::CH,
        encrypted_extensions: EarlyData::EE,
        new_session_ticket: EarlyData::NST
      },
      SupportedVersions::TYPE => {
        client_hello: SupportedVersions::CH,
        server_hello: SupportedVersions::SH,
        hello_retry_request: SupportedVersions::SH
      },
      Cookie::TYPE => { client_hello: Cookie, hello_retry_request: Cookie },
      PskKeyExchangeModes::TYPE => { client_hello: PskKeyExchangeModes },
      CertificateAuthorities::TYPE => { client_hello: CertificateAuthorities, certificate_request: CertificateAuthorities },
      PostHandshakeAuth::TYPE => { client_hello: PostHandshakeAuth },
      SignatureAlgorithmsCert::TYPE => { client_hello: SignatureAlgorithmsCert, certificate_request: SignatureAlgorithmsCert },
      KeyShare::TYPE => { client_hello: KeyShare::CH, server_hello: KeyShare::SH, hello_retry_request: KeyShare::HRR }
    })
  end
end
