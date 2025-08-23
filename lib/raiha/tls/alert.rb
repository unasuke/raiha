# frozen_string_literal: true

require_relative "../tls"
require "stringio"

module Raiha
  module TLS
    # Represents alerts of the TLS 1.3 protocol.
    #
    #  enum { warning(1), fatal(2), (255) } AlertLevel;
    #
    #  enum {
    #      close_notify(0),
    #      unexpected_message(10),
    #      bad_record_mac(20),
    #      record_overflow(22),
    #      handshake_failure(40),
    #      bad_certificate(42),
    #      unsupported_certificate(43),
    #      certificate_revoked(44),
    #      certificate_expired(45),
    #      certificate_unknown(46),
    #      illegal_parameter(47),
    #      unknown_ca(48),
    #      access_denied(49),
    #      decode_error(50),
    #      decrypt_error(51),
    #      protocol_version(70),
    #      insufficient_security(71),
    #      internal_error(80),
    #      inappropriate_fallback(86),
    #      user_canceled(90),
    #      missing_extension(109),
    #      unsupported_extension(110),
    #      unrecognized_name(112),
    #      bad_certificate_status_response(113),
    #      unknown_psk_identity(115),
    #      certificate_required(116),
    #      no_application_protocol(120),
    #      (255)
    #  } AlertDescription;
    #
    #  struct {
    #      AlertLevel level;
    #      AlertDescription description;
    #  } Alert;
    #
    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-6
    class Alert
      attr_accessor :level
      attr_accessor :description

      DESCRIPTIONS = {
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
        120 => :no_application_protocol,
      }

      def self.level_num_to_sym(level_num)
        case level_num
        when 1
          :warning
        when 2
          :fatal
        else
          :unknown
        end
      end

      def self.description_num_to_sym(description_num)
        DESCRIPTIONS[description_num] || :unknown
      end

      def self.deserialize(data)
        buf = StringIO.new(data)

        level = buf.read(1).unpack1("C")
        desc = buf.read(1).unpack1("C")
        self.new(level: level, description: desc)
      end

      def initialize(level:, description:)
        @level = level
        @description = description
      end

      def serialize
        buf = String.new(encoding: "BINARY")
        buf << [@level].pack("C*")
        buf << [@description].pack("C*")
        buf
      end

      def warning?
        @level == 1
      end

      def fatal?
        @level == 2
      end
    end
  end
end
