# frozen_string_literal: true

require_relative "../namespace"

# The HTTP/3 layer's module, opened here rather than through "../http3" so
# that QPACK loads alone, without the frames of HTTP/3 or anything of QUIC.
module Raiha::Next::HTTP3
end

# QPACK (RFC 9204), field compression for HTTP/3. Knows neither the frames
# of HTTP/3 nor QUIC: it takes and gives the bytes of field sections and of
# the encoder and decoder streams.
module Raiha::Next::HTTP3::QPACK
end

require_relative "qpack/error_code"
require_relative "qpack/error"
require_relative "qpack/reader"
require_relative "qpack/writer"
require_relative "qpack/huffman"
