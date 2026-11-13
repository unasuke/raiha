# frozen_string_literal: true

module Raiha::QUIC
  # What makes the connection IDs an Endpoint issues: the first of each
  # connection, a Retry's, and those NEW_CONNECTION_ID frames carry. An
  # Endpoint takes one as `connection_ids:`, and its own draws random
  # bytes; one that puts a worker's ID in each, or a QUIC-LB server ID,
  # takes its place without the Endpoint changing.
  #
  # `generate(length)` gives an ID of `length` bytes, the Endpoint's
  # Config#connection_id_length; the Endpoint draws again while the ID is
  # in use. `worker_of(connection_id)` is the ID of the other worker that
  # issued `connection_id`, nil when it is this one's or no worker's, so
  # that the Endpoint can hand on what came for another worker.
  class RandomConnectionIDs
    def initialize(random)
      @random = random
    end

    def generate(length) = @random.bytes(length).b

    def worker_of(_connection_id) = nil
  end

  # The connection IDs of worker `worker_id` of `worker_count`, each
  # carrying the worker's ID in its first byte. Plain, that byte would let
  # an observer tell connection IDs of one connection from those of
  # another (RFC 9000 "Connection ID" forbids that), so it is the ID XOR
  # the first byte of an HMAC of the rest, under a key that `key`, the
  # Config's stateless_reset_key every worker shares, derives: the first
  # byte looks as random as the rest, and every worker reads it back.
  class WorkerConnectionIDs
    # The shortest ID a worker issues: the worker's byte and 3 random ones.
    MIN_LENGTH = 4
    MAX_WORKERS = 256
    LABEL = "raiha worker connection ID"

    def initialize(random, worker_id:, worker_count:, key:)
      raise ArgumentError, "worker_count #{worker_count} is not 1 to #{MAX_WORKERS}" unless (1..MAX_WORKERS).cover?(worker_count)
      raise ArgumentError, "worker_id #{worker_id} is not 0 to #{worker_count - 1}" unless (0...worker_count).cover?(worker_id)
      @random = random
      @worker_id = worker_id
      @worker_count = worker_count
      @key = Crypto::Mac.digest(key, LABEL)
    end

    def generate(length)
      raise ArgumentError, "a worker's connection ID is #{MIN_LENGTH} bytes at least, not #{length}" if length < MIN_LENGTH
      rest = @random.bytes(length - 1).b
      [@worker_id ^ mask(rest)].pack("C") + rest
    end

    def worker_of(connection_id)
      return nil if connection_id.bytesize < MIN_LENGTH
      rest = connection_id.byteslice(1..) #: String
      worker = connection_id.getbyte(0).to_i ^ mask(rest)
      worker == @worker_id || worker >= @worker_count ? nil : worker
    end

    private def mask(rest) = Crypto::Mac.digest(@key, rest).getbyte(0).to_i
  end
end
