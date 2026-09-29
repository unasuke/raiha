# frozen_string_literal: true

module Raiha::Next::TLS::Codec
  # A byte string from the peer that cannot be a valid message. `#alert` is the
  # TLS alert to abort the handshake with.
  class Malformed < StandardError
    def alert = :decode_error
  end

  # Fewer bytes than a length prefix or a fixed-size field says.
  class Truncated < Malformed; end

  # A vector length outside the bounds of its definition.
  class RangeViolation < Malformed; end

  # Bytes left over at the end of a vector.
  class TrailingData < Malformed; end

  # Two extensions of the same type in one extension block.
  class Duplicate < Malformed
    def alert = :illegal_parameter
  end

  # A known extension in a message it must not appear in.
  class IllegalPlacement < Malformed
    def alert = :illegal_parameter
  end

  # A handshake message type this implementation does not know. On the state
  # machine's path `Reassembler#expect` rejects it before parsing, so only
  # direct callers of `Handshake.parse` see this.
  class UnknownMessageType < Malformed
    def alert = :unexpected_message
  end

  # A value that cannot be written to the wire.
  class EncodeError < StandardError; end
end
