# frozen_string_literal: true

module Raiha::Quic
  module Handshake
    module EncryptionLevel
      INITIAL = :initial
      HANDSHAKE = :handshake
      ONE_RTT = :one_rtt
      ZERO_RTT = :zero_rtt

      ALL = [INITIAL, ZERO_RTT, HANDSHAKE, ONE_RTT].freeze
    end
  end
end
