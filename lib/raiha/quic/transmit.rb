# frozen_string_literal: true

module Raiha::QUIC
  # What to send: `payload` to `destination` ([host, port]) from `source`
  # (nil leaves it to the OS) with the ECN codepoint `ecn` (:not_ect, :ect0
  # or :ect1). With a `segment_size`, the payload is several datagrams of
  # that size, the last one possibly shorter, for GSO or to send one by one.
  class Transmit < Data.define(:payload, :destination, :source, :ecn, :segment_size)
    ECN = %i[not_ect ect0 ect1].freeze
    # The most datagrams a connection puts in one: what Linux's GSO takes
    # at most (UDP_MAX_SEGMENTS).
    MAX_SEGMENTS = 64
  end
end
