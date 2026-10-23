# frozen_string_literal: true

module Raiha::Next::HTTP3::QPACK
  # Bytes from the peer that do not decode. Raised inside QPACK and turned
  # into a Failure where the bytes came in, whose error code depends on
  # the stream they came on; the caller never sees it.
  class Malformed < StandardError; end

  # The bytes ran out before a field did. On the encoder and decoder
  # streams the rest is yet to come; a field section is always whole.
  class Truncated < Malformed; end

  # An integer larger than QPACK has to decode (RFC 9204 "Implementation
  # Limits"): a stream error on a request stream, unlike the rest.
  class IntegerOverflow < Malformed; end

  # A string longer than the caller allows, found out before its bytes are
  # taken: past the capacity of the dynamic table on the encoder stream,
  # past the budget in a field section. Not malformed in itself.
  class TooLong < StandardError; end
end
