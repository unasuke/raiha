# frozen_string_literal: true

module Raiha::QUIC
  # A session a QUIC client may resume, as a value: the TLS layer's, the
  # server's transport parameters that 0-RTT may use (RFC 9000 "Values of
  # Transport Parameters for 0-RTT"), and the ALPN protocol and QUIC
  # version of the connection the ticket came on, which 0-RTT keeps. The
  # application keeps it where it likes, `to_h` and `from_h` turning it into
  # plain values and back.
  class Session < Data.define(:tls, :transport_parameters, :alpn, :version)
    def to_h = { tls: tls.to_h, transport_parameters: transport_parameters.to_h, alpn:, version: }

    def self.from_h(hash)
      raise ArgumentError, "a session is a Hash" unless hash.is_a?(Hash)
      parameters = hash.fetch(:transport_parameters)
      unless parameters.is_a?(Hash) && parameters.keys.sort == RememberedTransportParameters.members.sort
        raise ArgumentError, "transport_parameters must name every remembered parameter"
      end
      alpn = hash.fetch(:alpn)
      raise ArgumentError, "alpn must be a String or nil" unless alpn.nil? || alpn.is_a?(String)
      version = hash.fetch(:version)
      raise ArgumentError, "version must be an Integer" unless version.is_a?(Integer)
      tls = hash.fetch(:tls)
      raise ArgumentError, "tls must be a Hash" unless tls.is_a?(Hash)
      new(tls: Raiha::TLS::Session.from_h(tls), transport_parameters: remembered(parameters), alpn: alpn&.b&.freeze, version:)
    rescue KeyError => e
      raise ArgumentError, "a session lacks #{e.key}"
    end

    private_class_method def self.remembered(parameters)
      values = parameters.to_h do |name, value|
        case name
        when :max_idle_timeout
          raise ArgumentError, "max_idle_timeout must be a Numeric of 0 or more" unless value.is_a?(Numeric) && !value.negative?
          [name, Float(value)]
        when :disable_active_migration
          raise ArgumentError, "disable_active_migration must be true or false" unless value == true || value == false
          [name, value]
        else
          raise ArgumentError, "#{name} must be an Integer of 0 or more" unless value.is_a?(Integer) && !value.negative?
          [name, value]
        end
      end
      RememberedTransportParameters.new(**values) # steep:ignore
    end
  end
end
