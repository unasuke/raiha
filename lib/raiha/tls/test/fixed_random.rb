# frozen_string_literal: true

module Raiha::TLS::Test
  # A random source that hands out given bytes in order, so that tests can
  # reproduce the randoms of RFC 8448. Each draw must ask for exactly the
  # length of the next chunk. Never use it outside tests.
  class FixedRandom
    def initialize(*chunks)
      @chunks = chunks.map { |chunk| chunk.b.freeze }
    end

    def bytes(length)
      chunk = @chunks.shift or raise ArgumentError, "no fixed bytes left"
      raise ArgumentError, "asked for #{length} bytes, the next chunk is #{chunk.bytesize}" unless chunk.bytesize == length
      chunk
    end
  end
end
