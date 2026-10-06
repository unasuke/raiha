# frozen_string_literal: true

module Raiha::Next::QUIC
  # What to send: `payload` to `destination` ([host, port]) from `source`
  # (nil leaves it to the OS) with the ECN codepoint `ecn` (:not_ect, :ect0
  # or :ect1). With a `segment_size`, the payload is several datagrams of
  # that size, the last one possibly shorter, for GSO or to send one by one.
  class Transmit < Data.define(:payload, :destination, :source, :ecn, :segment_size)
    ECN = %i[not_ect ect0 ect1].freeze
  end
end
