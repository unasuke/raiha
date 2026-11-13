# frozen_string_literal: true

# Names for the integers on the wire. Values stay Integers everywhere else,
# so an out-of-date table cannot break parsing. These tables are used only at
# the public API boundary and for logs, qlog and `inspect`.
module Raiha::Next::TLS::IANA
  CIPHER_SUITES = {
    0x1301 => :TLS_AES_128_GCM_SHA256,
    0x1302 => :TLS_AES_256_GCM_SHA384,
    0x1303 => :TLS_CHACHA20_POLY1305_SHA256,
    0x1304 => :TLS_AES_128_CCM_SHA256,
    0x1305 => :TLS_AES_128_CCM_8_SHA256
  }.freeze #: Hash[Integer, Symbol]

  NAMED_GROUPS = {
    0x0017 => :secp256r1,
    0x0018 => :secp384r1,
    0x0019 => :secp521r1,
    0x001d => :x25519,
    0x001e => :x448,
    0x0100 => :ffdhe2048,
    0x0101 => :ffdhe3072,
    0x0102 => :ffdhe4096,
    0x0103 => :ffdhe6144,
    0x0104 => :ffdhe8192,
    0x0200 => :MLKEM512,
    0x0201 => :MLKEM768,
    0x0202 => :MLKEM1024,
    0x11eb => :SecP256r1MLKEM768,
    0x11ec => :X25519MLKEM768,
    0x11ed => :SecP384r1MLKEM1024
  }.freeze #: Hash[Integer, Symbol]

  EXTENSIONS = {
    0 => :server_name,
    1 => :max_fragment_length,
    5 => :status_request,
    10 => :supported_groups,
    13 => :signature_algorithms,
    14 => :use_srtp,
    15 => :heartbeat,
    16 => :application_layer_protocol_negotiation,
    17 => :status_request_v2,
    18 => :signed_certificate_timestamp,
    19 => :client_certificate_type,
    20 => :server_certificate_type,
    21 => :padding,
    27 => :compress_certificate,
    28 => :record_size_limit,
    35 => :session_ticket,
    41 => :pre_shared_key,
    42 => :early_data,
    43 => :supported_versions,
    44 => :cookie,
    45 => :psk_key_exchange_modes,
    47 => :certificate_authorities,
    48 => :oid_filters,
    49 => :post_handshake_auth,
    50 => :signature_algorithms_cert,
    51 => :key_share,
    57 => :quic_transport_parameters,
    0xfe0d => :encrypted_client_hello,
    0xff01 => :renegotiation_info
  }.freeze #: Hash[Integer, Symbol]

  ALERTS = {
    0 => :close_notify,
    10 => :unexpected_message,
    20 => :bad_record_mac,
    22 => :record_overflow,
    40 => :handshake_failure,
    42 => :bad_certificate,
    43 => :unsupported_certificate,
    44 => :certificate_revoked,
    45 => :certificate_expired,
    46 => :certificate_unknown,
    47 => :illegal_parameter,
    48 => :unknown_ca,
    49 => :access_denied,
    50 => :decode_error,
    51 => :decrypt_error,
    70 => :protocol_version,
    71 => :insufficient_security,
    80 => :internal_error,
    86 => :inappropriate_fallback,
    90 => :user_canceled,
    109 => :missing_extension,
    110 => :unsupported_extension,
    112 => :unrecognized_name,
    113 => :bad_certificate_status_response,
    115 => :unknown_psk_identity,
    116 => :certificate_required,
    117 => :general_error,
    120 => :no_application_protocol
  }.freeze #: Hash[Integer, Symbol]

  ALERT_CODES = ALERTS.invert.freeze #: Hash[Symbol, Integer]

  # nil for a value this table does not know.
  def self.cipher_suite_name(v) = CIPHER_SUITES[v]

  def self.alert_name(v) = ALERTS[v]

  # Only for alerts this implementation sends, so a missing name is a bug
  # here and raises KeyError.
  def self.alert_code(name) = ALERT_CODES.fetch(name)

  # A name for logs, qlog and `inspect`, including values the table lacks.
  def self.label(table, v) = table[v]&.to_s || format("unknown(0x%04x)", v)

  # RFC 8701 GREASE values: 0x0A0A, 0x1A1A, ..., 0xFAFA.
  def self.grease?(v) = (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
end
