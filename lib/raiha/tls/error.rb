# frozen_string_literal: true

require_relative "iana"

module Raiha::Next::TLS
  # Misuse of the API by the caller, as opposed to bad bytes from the peer,
  # which never raise.
  class UsageError < StandardError; end

  # TCP::Socket's failure, before or after the handshake completed. `alert`
  # is the one we sent, nil if none; `reason` names the check that failed.
  class HandshakeError < StandardError
    attr_reader :alert, :reason

    def initialize(message = nil, alert: nil, reason: nil)
      super(message)
      @alert = alert
      @reason = reason
    end
  end

  # A HandshakeError over a certificate that did not pass.
  class CertificateError < HandshakeError; end

  # TCP::Socket was sent an alert that ends the connection. Both values are
  # the peer's, so they stay Integers.
  class AlertError < StandardError
    attr_reader :level, :description

    def initialize(level:, description:)
      @level = level
      @description = description
      super("the peer sent #{IANA.label(IANA::ALERTS, description)}")
    end
  end
end
