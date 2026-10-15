# frozen_string_literal: true

module Raiha::Next::TLS
  # What differs between TLS over TCP and TLS inside QUIC, as one set of
  # flags. RFC 9001 puts a number of "must not"s on the TLS side; gathering
  # them here keeps them out of the state machine's branches, and reading
  # `TCP` next to `QUIC` shows everything QUIC changes.
  class Profile < Data.define(
    :record_layer,
    :compatibility_mode,
    :reject_nonempty_session_id,
    :send_end_of_early_data,
    :allow_key_update_message,
    :required_extensions,
    :forbidden_extensions,
    :max_early_data_size_policy,
    :never_select_cipher_suites,
    :all_alerts_fatal,
    :require_alpn,
    :protocol_violation_reasons
  )
    QUIC_TRANSPORT_PARAMETERS = 0x39

    TCP = Ractor.make_shareable(new(
      record_layer: true,
      compatibility_mode: true,
      reject_nonempty_session_id: false,
      send_end_of_early_data: true,
      allow_key_update_message: true,
      required_extensions: [],
      # RFC 9001 "QUIC Transport Parameters Extension": an endpoint that
      # receives quic_transport_parameters over a TLS connection that is not
      # QUIC must abort with unsupported_extension.
      forbidden_extensions: [QUIC_TRANSPORT_PARAMETERS],
      max_early_data_size_policy: :free,
      never_select_cipher_suites: [],
      all_alerts_fatal: false,
      require_alpn: false,
      protocol_violation_reasons: []
    ))

    QUIC = Ractor.make_shareable(new(
      # RFC 9001 "Carrying TLS Messages": handshake messages go in CRYPTO
      # frames, not records.
      record_layer: false,
      # RFC 9001 "Prohibit TLS Middlebox Compatibility Mode": a client must
      # not request it, and a server should treat a nonempty
      # legacy_session_id as a PROTOCOL_VIOLATION.
      compatibility_mode: false,
      reject_nonempty_session_id: true,
      # RFC 9001 "Removing the EndOfEarlyData Message".
      send_end_of_early_data: false,
      # RFC 9001 "Key Update": a KeyUpdate message is a connection error.
      allow_key_update_message: false,
      # RFC 9001 "QUIC Transport Parameters Extension": missing_extension
      # without it.
      required_extensions: [QUIC_TRANSPORT_PARAMETERS],
      forbidden_extensions: [],
      # RFC 9001 "Enabling 0-RTT": max_early_data_size must be 0xffffffff.
      max_early_data_size_policy: :sentinel,
      # RFC 9001 "Header Protection" defines none for this suite. It is never
      # selected, but an offer of it is not rejected either.
      never_select_cipher_suites: %i[TLS_AES_128_CCM_8_SHA256],
      # QUIC carries only fatal errors, as CONNECTION_CLOSE.
      all_alerts_fatal: true,
      # RFC 9001 "Application-Layer Protocol Negotiation": QUIC endpoints must
      # agree on a protocol with ALPN, failing with no_application_protocol.
      require_alpn: true,
      # Failures the TLS core detects for which RFC 9001 asks for
      # PROTOCOL_VIOLATION rather than CRYPTO_ERROR. The QUIC binding looks up
      # Event::Failed#reason here.
      protocol_violation_reasons: %i[
        handshake_data_spans_key_change
        data_after_client_hello
        wrong_epoch
        post_handshake_certificate_request
        max_early_data_size_not_sentinel
        nonempty_legacy_session_id
      ]
    ))
  end
end
