# frozen_string_literal: true

module Raiha::HTTP3::QPACK
  # The HTTP/3 error codes QPACK defines (RFC 9204 "Error Handling").
  module ErrorCode
    # A field section could not be decoded.
    DECOMPRESSION_FAILED = 0x0200
    # An instruction on the encoder stream could not be followed.
    ENCODER_STREAM_ERROR = 0x0201
    # An instruction on the decoder stream could not be followed.
    DECODER_STREAM_ERROR = 0x0202
  end
end
