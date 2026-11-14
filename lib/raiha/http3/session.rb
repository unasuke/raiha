# frozen_string_literal: true

require_relative "../quic"
require_relative "settings"

module Raiha::HTTP3
  # A session an HTTP/3 client may resume, as a value: the QUIC layer's,
  # and the server's SETTINGS, which a 0-RTT attempt's first HTTP/3 layer
  # keeps to until the server's come (RFC 9114 "Initialization"; RFC 9204
  # "Maximum Dynamic Table Capacity"). The application keeps it where it
  # likes, `to_h` and `from_h` turning it into plain values and back.
  #
  # The one value of HTTP/3 that knows the QUIC layer, it is not loaded with
  # the rest of HTTP/3, which does not; the Runtime loads it.
  class Session < Data.define(:quic, :settings)
    def to_h = { quic: quic.to_h, settings: settings.to_h }

    def self.from_h(hash)
      raise ArgumentError, "a session is a Hash" unless hash.is_a?(Hash)
      quic = hash.fetch(:quic)
      settings = hash.fetch(:settings)
      raise ArgumentError, "quic and settings must be Hashes" unless quic.is_a?(Hash) && settings.is_a?(Hash)
      unless settings.keys.sort == Settings.members.sort
        raise ArgumentError, "settings must name every setting"
      end
      new(quic: Raiha::QUIC::Session.from_h(quic), settings: Settings.new(**settings))
    rescue KeyError => e
      raise ArgumentError, "a session lacks #{e.key}"
    end
  end
end
