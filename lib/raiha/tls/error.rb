# frozen_string_literal: true

module Raiha
  module TLS
    class Error < ::Raiha::Error
    end

    # Raised by Peer#verify_transcript_roundtrip! when the bytes stored in
    # TranscriptHash do not match a freshly produced Handshake#serialize,
    # i.e. either the deserialize/serialize round trip lost information
    # (receive path) or serialize is not deterministic (self-generated
    # path). Only raised when Config#transcript_hash_verify is true.
    class TranscriptRoundtripError < Error
    end
  end
end
