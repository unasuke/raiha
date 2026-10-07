# frozen_string_literal: true

require "securerandom"

module Raiha::Next::QUIC
  module Crypto
    # Where random bytes come from when no other source is given: connection
    # IDs, PATH_CHALLENGE data, the padding of a stateless reset. Anything
    # with `#bytes(n)` can take its place, and a seeded ::Random makes the
    # packets reproducible in tests; do not replace it anywhere else.
    Random = SecureRandom
  end
end
