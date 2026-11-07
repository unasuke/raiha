# frozen_string_literal: true

module Raiha::Next::QUIC
  # What makes the connection IDs an Endpoint issues: the first of each
  # connection, a Retry's, and those NEW_CONNECTION_ID frames carry. An
  # Endpoint takes one as `connection_ids:`, and its own draws random
  # bytes; one that puts a worker's ID in each, or a QUIC-LB server ID,
  # takes its place without the Endpoint changing.
  #
  # `generate(length)` gives an ID of `length` bytes, the Endpoint's
  # Config#connection_id_length; the Endpoint draws again while the ID is
  # in use.
  class RandomConnectionIDs
    def initialize(random)
      @random = random
    end

    def generate(length) = @random.bytes(length).b
  end
end
