# frozen_string_literal: true

module Raiha::Next::QUIC
  # The connections of one UDP socket (250 "Endpoint"). It finds the
  # connection a datagram belongs to by its Destination Connection ID and
  # decides for one that belongs to none: the offer of a new connection,
  # which the application takes or turns down, or nothing. A Connection
  # never refers to its Endpoint.
  #
  # Like a Connection it never reads a clock: `now:` is the monotonic clock,
  # and the wall clock its tokens expire by is `time:`, given once when it is
  # made.
  class Endpoint
    # How long an offer lasts unless the application decides on it, from
    # its first datagram (250 "handle has a lifetime").
    HANDLE_LIFETIME = 3.0
    # The bytes of datagrams an offer keeps until it becomes a connection,
    # and all offers together, so that what an attacker can make an
    # Endpoint keep is bounded whatever the application does.
    HANDLE_BUFFER = 64 * 1024
    HANDLES_BUFFER = 16 * 1024 * 1024

    # An offer of a new connection, until the application decides on it:
    # what the headers of the client's first Initial said, and the
    # datagrams that came for it. `destination_connection_id` is the one the
    # client chose, which its Initial keys come from; the client's first, the
    # original, differs from it after a Retry, as does
    # `retry_source_connection_id`, nil without one.
    class Handle
      attr_reader :remote, :destination_connection_id, :source_connection_id, :original_destination_connection_id,
        :retry_source_connection_id, :expires_at, :datagrams
      # The bytes of the datagrams kept.
      attr_reader :buffered

      def initialize(remote:, destination_connection_id:, source_connection_id:, original_destination_connection_id:,
        retry_source_connection_id:, expires_at:)
        @remote = remote
        @destination_connection_id = destination_connection_id
        @source_connection_id = source_connection_id
        @original_destination_connection_id = original_destination_connection_id
        @retry_source_connection_id = retry_source_connection_id
        @expires_at = expires_at
        @datagrams = [] #: Array[[String, address, address?, ecn | :ce]]
        @buffered = 0
      end

      # Keeps a datagram for the connection to take.
      def keep(datagram, from:, to:, ecn:)
        @buffered += datagram.bytesize
        @datagrams << [datagram, from, to, ecn]
      end

      def expired?(now) = now >= @expires_at

      private def instance_variables_to_inspect = %i[@remote @expires_at]
    end

    # An Endpoint of a server. `random` is what it draws its own random
    # bytes from (250 "Random"), and its keys when `config` has none.
    def self.server(config:, random:, time:, now:) = new(config:, random:, time:, now:)

    private_class_method :new

    def initialize(config:, random:, time:, now:)
      @config = config
      @random = random
      @time = time
      @created_at = now
      @retry_token_key = config.retry_token_key || random.bytes(Config::MIN_KEY_LENGTH).b
      # The connections by each connection ID that leads to them.
      @connections = {} #: Hash[String, Connection]
      # The offers by the Destination Connection ID of their Initials, and
      # the bytes they keep.
      @handles = {} #: Hash[String, Handle]
      @buffered = 0
    end

    # What to do with `datagram`, which came from `from` to `to` with the
    # ECN codepoint `ecn`: a Route, or nil when an offer keeps it. Nothing
    # the peer sends raises.
    def receive(datagram, from:, to: nil, ecn: :not_ect, now:)
      packet = Wire::Packet.parse(datagram, dcid_length: @config.connection_id_length)
      case packet
      when Wire::Packet::Parsed then route(packet.header, datagram, from:, to:, ecn:, now:)
      when Wire::UnsupportedVersion then Route::Drop.new(reason: :unsupported_version)
      else Route::Drop.new(reason: :unexpected_packet)
      end
    rescue Wire::Malformed
      Route::Drop.new(reason: :malformed)
    end

    # Each datagram the connections have to send now.
    def each_transmit(now:, &)
      each_connection { |connection| connection.each_transmit(now:, &) }
    end

    # When something is to be done next: a connection's timer or the end of
    # an offer.
    def next_timeout
      [*connections.filter_map(&:next_timeout), *@handles.each_value.map(&:expires_at)].min
    end

    # Runs out what is due at `now`: the timers of the connections, and the
    # offers no one decided on. A connection that has closed is let go.
    def handle_timeout(now:)
      connections.each { |connection| connection.handle_timeout(now:) }
      @handles.each_value.select { |handle| handle.expired?(now) }.each { |handle| forget(handle) }
      @connections.delete_if { |_, connection| connection.closed? }
    end

    def each_connection(&) = connections.each(&)

    def connection_count = connections.size

    private def connections = @connections.values.uniq

    # Where a packet with a header that reads goes: to the connection of its
    # Destination Connection ID, else, for a client's Initial, to the offer
    # of a new connection.
    private def route(header, datagram, from:, to:, ecn:, now:)
      if (connection = @connections[header.dcid])
        connection.receive(datagram, from:, to:, ecn:, now:)
        return Route::Deliver.new(connection:)
      end
      return Route::Drop.new(reason: :unknown_connection_id) if header.is_a?(Wire::ShortHeader)
      if (handle = @handles[header.dcid])
        # Before the server answers, the client sends only Initial and 0-RTT
        # packets, from where its first came.
        return Route::Drop.new(reason: :address_mismatch) unless from == handle.remote
        return Route::Drop.new(reason: :unexpected_packet) if header.type == :handshake
        return keep(handle, datagram, from:, to:, ecn:)
      end
      return Route::Drop.new(reason: :unknown_connection_id) unless header.type == :initial
      # RFC 9000 "Datagram Size": a server drops an Initial in a datagram
      # under 1200 bytes.
      return Route::Drop.new(reason: :too_short) if datagram.bytesize < Connection::MIN_INITIAL_DATAGRAM
      offer(header, datagram, from:, to:, ecn:, now:)
    end

    # The first stage of a new connection, from the headers alone: no key
    # is derived and nothing is decrypted (250 "Endpoint"). A Retry token
    # shows the client receives at its address and carries its first
    # Destination Connection ID (RFC 9000 "Address Validation Using Retry
    # Packets"); one that does not verify is dropped. A token of another
    # kind is as none.
    private def offer(header, datagram, from:, to:, ecn:, now:)
      odcid = header.dcid
      retry_scid = nil #: String?
      unless header.token.empty? || header.token.getbyte(0) != RetryToken::KIND
        odcid = RetryToken.verify(header.token, key: @retry_token_key, address: from, time: wall_clock(now))
        return Route::Drop.new(reason: :invalid_token) unless odcid
        retry_scid = header.dcid
      end
      handle = Handle.new(remote: from, destination_connection_id: header.dcid, source_connection_id: header.scid,
        original_destination_connection_id: odcid, retry_source_connection_id: retry_scid, expires_at: now + HANDLE_LIFETIME)
      if (dropped = keep(handle, datagram, from:, to:, ecn:))
        return dropped
      end
      @handles[header.dcid] = handle
      Route::Incoming.new(handle:, remote: from, address_validated: !retry_scid.nil?)
    end

    # Keeps `datagram` with the offer `handle`; nil, or a Route::Drop when
    # the offer or all of them keep as much as they may.
    private def keep(handle, datagram, from:, to:, ecn:)
      size = datagram.bytesize
      return Route::Drop.new(reason: :buffer_full) if handle.buffered + size > HANDLE_BUFFER || @buffered + size > HANDLES_BUFFER
      handle.keep(datagram, from:, to:, ecn:)
      @buffered += size
      nil
    end

    private def forget(handle)
      @handles.delete(handle.destination_connection_id)
      @buffered -= handle.buffered
    end

    # The wall clock at `now`.
    private def wall_clock(now) = @time + (now - @created_at)

    private def instance_variables_to_inspect = %i[@config]
  end
end
