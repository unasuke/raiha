# frozen_string_literal: true

module Raiha::Next::QUIC
  # The connections of one UDP socket. It finds the
  # connection a datagram belongs to by its Destination Connection ID and
  # decides for one that belongs to none: the offer of a new connection,
  # which the application takes or turns down, a Version Negotiation, a
  # Stateless Reset, a CONNECTION_CLOSE for a Retry token that does not
  # verify, or nothing. A Connection never refers to its Endpoint.
  #
  # A client's Endpoint makes its connections with `connect` and takes no
  # offers; a Version Negotiation or a Retry goes to the connection it is
  # for. Either finds a Stateless Reset of its peers among the datagrams of
  # no connection.
  #
  # Like a Connection it never reads a clock: `now:` is the monotonic clock,
  # and the wall clock its tokens expire by is `time:`, given once when it is
  # made.
  class Endpoint
    # RFC 9000 "Stateless Reset": a reset is shorter than the packet that
    # triggered it, so that two endpoints cannot keep one going, and no
    # longer than this, one byte short of the 43 bytes RFC 9000 has resets
    # match, so that a reset reflects little.
    MAX_RESET_LENGTH = 42
    # RFC 9000 "Looping": each address is sent resets from a token bucket of
    # RESET_BURST, refilled at RESET_RATE a second. At most RESET_ADDRESSES
    # buckets are kept, the least recently used going first, so that no
    # address is shut out. An address whose bucket went starts again with a
    # full one, so all resets together come from one more bucket, of
    # RESET_TOTAL_BURST refilled at RESET_TOTAL_RATE a second.
    RESET_BURST = 10.0
    RESET_RATE = 1.0
    RESET_ADDRESSES = 1024
    RESET_TOTAL_BURST = 1000.0
    RESET_TOTAL_RATE = 100.0
    # How long an offer lasts unless the application decides on it, from
    # its first datagram, so that one the application forgets goes too.
    HANDLE_LIFETIME = 3.0
    # The bytes of datagrams an offer keeps until it becomes a connection,
    # and all offers together, so that what an attacker can make an
    # Endpoint keep is bounded whatever the application does.
    HANDLE_BUFFER = 64 * 1024
    HANDLES_BUFFER = 16 * 1024 * 1024
    # How many connection IDs an Endpoint draws for a new connection before
    # it gives up on finding one that leads to nothing yet.
    CONNECTION_ID_ATTEMPTS = 8

    # An offer of a new connection, until the application decides on it:
    # what the headers of the client's first Initial said, and the
    # datagrams that came for it. `destination_connection_id` is the one the
    # client chose, which its Initial keys come from; the client's first, the
    # original, differs from it after a Retry, as does
    # `retry_source_connection_id`, nil without one.
    #
    # Once admitted, the offer reads the ClientHello out of the Initial
    # packets with the client's Initial keys, into the TLS layer's Acceptor.
    class Handle
      attr_reader :remote, :version, :destination_connection_id, :source_connection_id, :original_destination_connection_id,
        :retry_source_connection_id, :expires_at, :datagrams
      # Whether the client's address is validated, by a Retry or by a token
      # of NEW_TOKEN.
      attr_reader :address_validated
      # The bytes of the datagrams kept.
      attr_reader :buffered

      def initialize(remote:, version:, destination_connection_id:, source_connection_id:, original_destination_connection_id:,
        retry_source_connection_id:, expires_at:, address_validated:)
        @remote = remote
        @address_validated = address_validated
        @version = version
        @destination_connection_id = destination_connection_id
        @source_connection_id = source_connection_id
        @original_destination_connection_id = original_destination_connection_id
        @retry_source_connection_id = retry_source_connection_id
        @expires_at = expires_at
        @datagrams = [] #: Array[[String, address, address?, ecn | :ce]]
        @buffered = 0
        @acceptor = nil #: Raiha::Next::TLS::Handshake::Acceptor?
        @keys = nil #: Crypto::Keys?
        @crypto = CryptoStream.new(:initial)
        @largest = nil #: Integer?
        @violation = nil #: Violation?
        @offered = false
      end

      # Keeps a datagram for the connection to take.
      def keep(datagram, from:, to:, ecn:)
        @buffered += datagram.bytesize
        @datagrams << [datagram, from, to, ecn]
      end

      def expired?(now) = now >= @expires_at

      def admitted? = !@acceptor.nil?

      # Starts reading the ClientHello, from the datagrams kept so far.
      # `time` is the wall clock; short header packets have connection IDs
      # of `dcid_length` bytes.
      def admit(time:, dcid_length:)
        @acceptor = Raiha::Next::TLS::Handshake::Acceptor.new
        @keys = Crypto::Initial.derive(dcid: @destination_connection_id, version: @version).client
        @datagrams.each { |datagram, *| read(datagram, time:, dcid_length:) }
      end

      # Reads the CRYPTO frames of the Initial packets of `datagram` that
      # open into the Acceptor. What breaks a rule once a packet has opened
      # ends the ClientHello. Once it is whole, nothing more is read: anyone
      # who saw the client's Initial can make Initial packets, and the
      # connection, which reads them all again, is to judge them.
      def read(datagram, time:, dcid_length:)
        acceptor = @acceptor or return
        keys = @keys or return
        return if acceptor.accepted
        offset = 0
        while offset < datagram.bytesize && !failed?
          packet = parse(datagram, offset, dcid_length) or break
          offset = packet.end_offset
          next unless packet.header.type == :initial && packet.header.dcid == @destination_connection_id
          unmasked = packet.unmask(keys.header_protection, largest: @largest)
          payload = unmasked.open(keys.aead) or next
          @largest = unmasked.packet_number if @largest.nil? || unmasked.packet_number > @largest # steep:ignore
          Wire::Frame.parse(payload, packet_type: :initial, ack_delay_exponent: Connection::DEFAULT_ACK_DELAY_EXPONENT).each do |frame|
            @crypto.receive(frame.offset, frame.data, limit: Raiha::Next::TLS::Handshake::Acceptor::MAX_CLIENT_HELLO_SIZE) if frame.is_a?(Wire::Frame::Crypto)
          end
          bytes = @crypto.read
          acceptor.receive(bytes, epoch: :initial, now: time) unless bytes.empty?
        end
      rescue Violation => error
        @violation = error
      end

      # Why the ClientHello could not be read, as the error to close with:
      # its CRYPTO frames broke a rule, or the Acceptor failed on what they
      # carried (RFC 9001 "TLS Errors"). nil while it can be.
      def error
        if (violation = @violation)
          ConnectionError.new(code: violation.code, frame_type: violation.frame_type || 0, reason: violation.message, application: false)
        elsif (acceptor = @acceptor)&.failed?
          code = TLSBinding.error_code(Raiha::Next::TLS::Profile::QUIC, acceptor.alert, acceptor.reason)
          ConnectionError.new(code:, frame_type: CryptoStream::FRAME_TYPE, reason: acceptor.reason.to_s, application: false)
        end
      end

      def failed? = !error.nil?

      # Turns the whole ClientHello down with the TLS alert `description`,
      # one of the Acceptor's REJECT_ALERTS (another raises ArgumentError),
      # and gives the error to close with.
      def reject(description)
        acceptor = @acceptor
        raise Error::StateError, "the ClientHello of the offer is not whole yet" unless acceptor&.accepted
        acceptor.reject(description)
        error or raise Error::StateError, "the Acceptor took no alert"
      end

      # The address the first datagram came to, which an answer goes from.
      def local = @datagrams.dig(0, 2)

      # The ClientHello once whole, nil before.
      def accepted = @acceptor&.accepted

      # The ClientHello, the first time it is whole and asked for.
      def take_client_hello
        return nil if @offered
        accepted = self.accepted or return nil
        @offered = true
        accepted
      end

      # The packet at `offset` in `datagram`; nil when there is none, or its
      # header does not read, which ends the datagram as anyone could have
      # sent it.
      private def parse(datagram, offset, dcid_length)
        packet = Wire::Packet.parse(datagram, offset:, dcid_length:)
        packet if packet.is_a?(Wire::Packet::Parsed)
      rescue Wire::Malformed
        nil
      end

      private def instance_variables_to_inspect = %i[@remote @expires_at]
    end

    # How a connection has its Endpoint make connection IDs that lead to
    # it, each with its stateless reset token, for NEW_CONNECTION_ID frames,
    # and forget those the peer retired.
    class Issuer
      def initialize(issue, forget)
        @issue = issue
        @forget = forget
      end

      def issue(connection) = @issue.call(connection)

      def forget(connection_id) = @forget.call(connection_id)
    end

    # An Endpoint of a server. `random` is what it draws its own random
    # bytes from, a seeded Random in tests, and its keys when `config` has
    # none. `connection_ids` makes the connection IDs it issues
    # (RandomConnectionIDs).
    def self.server(config:, random:, time:, now:, connection_ids: RandomConnectionIDs.new(random))
      new(role: :server, config:, random:, time:, now:, connection_ids:)
    end

    # An Endpoint of a client.
    def self.client(config:, random:, time:, now:, connection_ids: RandomConnectionIDs.new(random))
      new(role: :client, config:, random:, time:, now:, connection_ids:)
    end

    private_class_method :new

    def initialize(role:, config:, random:, time:, now:, connection_ids:)
      @role = role
      @config = config
      @random = random
      @connection_ids = connection_ids
      # Zero-length connection IDs lead to no connection of their own, and
      # are never issued.
      @issuer = config.connection_id_length.zero? ? nil : Issuer.new(->(connection) { issue_connection_id(connection) }, ->(id) { @connections.delete(id) })
      @time = time
      @created_at = now
      @retry_token_key = config.retry_token_key || random.bytes(Config::MIN_KEY_LENGTH).b
      @new_token_key = NewToken.key(@retry_token_key)
      @stateless_reset_key = config.stateless_reset_key || random.bytes(Config::MIN_KEY_LENGTH).b
      # The connections by each connection ID that leads to them, and by the
      # peer's address.
      @connections = {} #: Hash[String, Connection]
      @peers = {} #: Hash[address, Array[Connection]]
      # The offers by the Destination Connection ID of their Initials, and
      # the bytes they keep.
      @handles = {} #: Hash[String, Handle]
      @buffered = 0
      # What the Endpoint sends itself, for the offers.
      @transmits = [] #: Array[Transmit]
      # What is left of each address's stateless resets and of all of them,
      # and when.
      @resets = {} #: Hash[address, [Float, Float]]
      @reset_total = RESET_TOTAL_BURST
      @reset_total_at = now
    end

    # What to do with `datagram`, which came from `from` to `to` with the
    # ECN codepoint `ecn`: a Route, or nil when an offer keeps it. Nothing
    # the peer sends raises.
    def receive(datagram, from:, to: nil, ecn: :not_ect, now:)
      packet = Wire::Packet.parse(datagram, dcid_length: @config.connection_id_length)
      case packet
      when Wire::Packet::Parsed then route(packet.header, datagram, from:, to:, ecn:, now:)
      when Wire::UnsupportedVersion
        @role == :server ? negotiate(packet, datagram, from, to) : Route::Drop.new(reason: :unsupported_version)
      else
        @role == :client ? deliver(packet.dcid, datagram, from:, to:, ecn:, now:) : Route::Drop.new(reason: :unexpected_packet)
      end
    rescue Wire::Malformed
      (connection = reset_of(datagram, from, now)) ? Route::Deliver.new(connection:) : Route::Drop.new(reason: :malformed)
    end

    # A new client connection to `remote` with the TLS settings given, its
    # first Initial waiting to be sent, found by the Source Connection ID
    # the Endpoint chooses for it. A server's Endpoint connects to no one:
    # Error::Usage.
    def connect(tls_config:, keyring:, server_name:, remote:, now:, tracer: nil, keylog: nil, token: nil, session: nil, early_data: false)
      raise Error::Usage, "a server's Endpoint does not connect" unless @role == :client
      scid = new_connection_id
      connection = Connection.client(config: @config, tls_config:, keyring:, server_name:, remote:, time: wall_clock(now), now:, tracer:,
        keylog:, source_connection_id: scid, token:, session:, early_data:, issuer: @issuer)
      add(connection, [scid], remote)
    end

    # Each datagram to send now: the Endpoint's own, then the connections'.
    def each_transmit(now:, &)
      while (transmit = @transmits.shift)
        yield transmit
      end
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
      @peers.each_value { |peers| peers.delete_if(&:closed?) }
      @peers.delete_if { |_, peers| peers.empty? }
    end

    # The second stage of the offer of `handle`: the Endpoint reads the
    # ClientHello out of its Initial packets, sending nothing meanwhile, ACKs
    # included. Route::ClientHello when it is whole by now, else nil; the
    # datagrams to come complete it. A ClientHello that cannot be read ends
    # the offer with a CONNECTION_CLOSE.
    def admit(handle, now:)
      pending!(handle)
      raise Error::StateError, "the offer is admitted already" if handle.admitted?
      handle.admit(time: wall_clock(now), dcid_length: @config.connection_id_length)
      client_hello(handle)
    end

    # Takes the offer of `handle`, whose ClientHello is whole, as a new
    # connection with the TLS settings the application chose by it, and
    # returns the Connection. It is given the datagrams the offer kept, and
    # is found from now on by its own connection ID, which the Endpoint
    # chooses and gives the stateless reset token of, and by the one the
    # client chose. It sends the client a token of NEW_TOKEN for its later
    # connections, once it confirms the handshake. `anti_replay` and
    # `app_early_data_context` go to Connection.server, for 0-RTT.
    def accept(handle, tls_config:, keyring:, now:, tracer: nil, keylog: nil, anti_replay: nil, app_early_data_context: "".b)
      pending!(handle)
      accepted = handle.accepted or raise Error::StateError, "the ClientHello of the offer is not whole yet"
      scid = new_connection_id
      token = StatelessReset.token(key: @stateless_reset_key, connection_id: scid) unless scid.empty?
      new_token = NewToken.mint(key: @new_token_key, address: handle.remote, version: handle.version.number, time: wall_clock(now),
        random: @random)
      connection = Connection.server(config: @config, tls_config:, keyring:, time: wall_clock(now), now:, tracer:, keylog:,
        client_hello: accepted, original_destination_connection_id: handle.original_destination_connection_id,
        retry_source_connection_id: handle.retry_source_connection_id, address_validated: handle.address_validated,
        source_connection_id: scid, stateless_reset_token: token, new_token:, anti_replay:, app_early_data_context:, issuer: @issuer)
      forget(handle)
      add(connection, [scid, handle.destination_connection_id], handle.remote)
      handle.datagrams.each { |datagram, from, to, ecn| connection.receive(datagram, from:, to:, ecn:, now:) }
      connection
    end

    # Turns down the offer of `handle`, whose ClientHello is whole, with the
    # TLS alert `description` as CRYPTO_ERROR, as the application chose by
    # the ClientHello. It is one of those the Acceptor rejects with;
    # another raises ArgumentError.
    def reject(handle, description)
      pending!(handle)
      close(handle, handle.reject(description))
    end

    # Turns down the offer of `handle`, at either stage, with the transport
    # error `error_code` in a CONNECTION_CLOSE: CONNECTION_REFUSED, say,
    # for a server that takes no more connections.
    def refuse(handle, error_code: ErrorCode::CONNECTION_REFUSED)
      pending!(handle)
      close(handle, ConnectionError.new(code: error_code, frame_type: 0, reason: "", application: false))
    end

    # Answers the offer of `handle`, at either stage, with a Retry (RFC 9000
    # "Address Validation Using Retry Packets"): a token of the client's
    # first connection ID and address, which the Initial it sends next
    # brings back to show it receives there, and a connection ID it sends
    # that Initial to. An offer whose Initial brought a Retry token already
    # cannot have another: Error::Usage.
    def retry(handle, now:)
      pending!(handle)
      raise Error::Usage, "an offer after a Retry cannot be retried" if handle.retry_source_connection_id
      token = RetryToken.mint(key: @retry_token_key, original_destination_connection_id: handle.original_destination_connection_id,
        address: handle.remote, time: wall_clock(now))
      packet = Wire::Retry.new(version: handle.version, dcid: handle.source_connection_id, scid: new_connection_id, token:)
      @transmits << transmit(packet.seal(handle.destination_connection_id), handle.remote, handle.local)
      forget(handle)
    end

    def each_connection(&) = connections.each(&)

    def connection_count = connections.size

    private def connections = @connections.values.uniq

    # Where a packet with a header that reads goes: to the connection of its
    # Destination Connection ID, else, for a short header, to a connection
    # it is a Stateless Reset of, and at a server, for a client's Initial,
    # to the offer of a new connection, and for a short header, a Stateless
    # Reset.
    private def route(header, datagram, from:, to:, ecn:, now:)
      return deliver(header.dcid, datagram, from:, to:, ecn:, now:) if @connections.key?(header.dcid)
      if header.is_a?(Wire::ShortHeader)
        if (connection = reset_of(datagram, from, now))
          return Route::Deliver.new(connection:)
        end
        return @role == :server ? reset(header.dcid, datagram, from, to, now) : Route::Drop.new(reason: :unknown_connection_id)
      end
      return Route::Drop.new(reason: :unknown_connection_id) unless @role == :server
      if (handle = @handles[header.dcid])
        # Before the server answers, the client sends only Initial and 0-RTT
        # packets, from where its first came.
        return Route::Drop.new(reason: :address_mismatch) unless from == handle.remote
        return Route::Drop.new(reason: :unexpected_packet) if header.type == :handshake
        if (dropped = keep(handle, datagram, from:, to:, ecn:))
          return dropped
        end
        return nil unless handle.admitted?
        handle.read(datagram, time: wall_clock(now), dcid_length: @config.connection_id_length)
        return client_hello(handle)
      end
      return Route::Drop.new(reason: :unknown_connection_id) unless header.type == :initial
      # RFC 9000 "Datagram Size": a server drops an Initial in a datagram
      # under 1200 bytes.
      return Route::Drop.new(reason: :too_short) if datagram.bytesize < Connection::MIN_INITIAL_DATAGRAM
      offer(header, datagram, from:, to:, ecn:, now:)
    end

    # The first stage of a new connection, from the headers alone: no key
    # is derived and nothing is decrypted, so that a Retry or a refusal
    # costs little under attack. A Retry token
    # shows the client receives at its address and carries its first
    # Destination Connection ID (RFC 9000 "Address Validation Using Retry
    # Packets"); one that does not verify is answered with a CONNECTION_CLOSE
    # of INVALID_TOKEN, as the client would not take another Retry (the same
    # section). A token of NEW_TOKEN that is valid shows the same of the
    # address; one that is not is as none, and the application may still send
    # a Retry (RFC 9000 "Address Validation for Future Connections"). A
    # token of another kind is as none.
    #
    # Without a Retry, the connection ID is the client's first, which RFC
    # 9000 "Negotiating Connection IDs" has 8 bytes at least, and an
    # Initial with a shorter one is dropped; after one, it is the server's.
    private def offer(header, datagram, from:, to:, ecn:, now:)
      odcid = header.dcid
      retry_scid = nil #: String?
      unless header.token.empty? || header.token.getbyte(0) != RetryToken::KIND
        odcid = RetryToken.verify(header.token, key: @retry_token_key, address: from, time: wall_clock(now))
        unless odcid
          error = ConnectionError.new(code: ErrorCode::INVALID_TOKEN, frame_type: 0, reason: "", application: false)
          packet = close_packet(header.version, client_dcid: header.dcid, client_scid: header.scid, error:)
          return Route::Respond.new(transmit: transmit(packet, from, to))
        end
        retry_scid = header.dcid
      end
      return Route::Drop.new(reason: :short_connection_id) if retry_scid.nil? && header.dcid.bytesize < Connection::INITIAL_DCID_LENGTH
      validated = !retry_scid.nil? || (header.token.getbyte(0) == NewToken::KIND &&
        NewToken.valid?(header.token, key: @new_token_key, address: from, version: header.version.number, time: wall_clock(now)))
      handle = Handle.new(remote: from, version: header.version, destination_connection_id: header.dcid, source_connection_id: header.scid,
        original_destination_connection_id: odcid, retry_source_connection_id: retry_scid, expires_at: now + HANDLE_LIFETIME,
        address_validated: validated)
      if (dropped = keep(handle, datagram, from:, to:, ecn:))
        return dropped
      end
      @handles[header.dcid] = handle
      Route::Incoming.new(handle:, remote: from, address_validated: validated)
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

    # What the second stage of `handle` has come to: Route::ClientHello the
    # first time the ClientHello is whole, nil before and when it could not
    # be read, which closes the offer.
    private def client_hello(handle)
      if (error = handle.error)
        close(handle, error)
        return nil
      end
      accepted = handle.take_client_hello or return nil
      Route::ClientHello.new(handle:, accepted:)
    end

    # Gives `datagram` to the connection of `dcid`.
    private def deliver(dcid, datagram, from:, to:, ecn:, now:)
      connection = @connections[dcid] or return Route::Drop.new(reason: :unknown_connection_id)
      connection.receive(datagram, from:, to:, ecn:, now:)
      Route::Deliver.new(connection:)
    end

    # RFC 9000 "Detecting a Stateless Reset": the connection to the address
    # `datagram` came from that takes it as a Stateless Reset of its peer,
    # which then drains; nil when none does. A reset has a connection ID of
    # no connection, or none that reads.
    private def reset_of(datagram, from, now) = @peers[from]&.find { |connection| connection.take_stateless_reset(datagram, now:) }

    # Keeps `connection`, found by `ids` and by the address of its peer.
    private def add(connection, ids, peer)
      ids.each { |id| @connections[id] = connection }
      (@peers[peer] ||= []) << connection
      connection
    end

    # Ends the offer of `handle` with a CONNECTION_CLOSE of `error` in an
    # Initial packet, the server's only, sealed with the server's Initial
    # keys of the client's connection ID (RFC 9000 "Immediate Close during
    # the Handshake"). It is far smaller than the Initial that came, as the
    # anti-amplification limit asks. Its Source Connection ID leads nowhere,
    # as no connection follows, so it is drawn with nothing to avoid.
    private def close(handle, error)
      packet = close_packet(handle.version, client_dcid: handle.destination_connection_id, client_scid: handle.source_connection_id, error:)
      @transmits << transmit(packet, handle.remote, handle.local)
      forget(handle)
    end

    # The server's Initial packet with a CONNECTION_CLOSE of `error` to the
    # client whose Initial had the connection IDs `client_dcid` and
    # `client_scid`.
    private def close_packet(version, client_dcid:, client_scid:, error:)
      reason = error.reason.b.byteslice(0, Connection::MAX_REASON_LENGTH) #: String
      frame = Wire::Frame::ConnectionClose.new(code: error.code, frame_type: error.frame_type, reason:, application: false)
      scid = @random.bytes(@config.connection_id_length).b
      header = Wire::LongHeader.new(type: :initial, version:, dcid: client_scid, scid:)
      keys = Crypto::Initial.derive(dcid: client_dcid, version:).server
      payload = Wire::Frame.encode([frame], ack_delay_exponent: Connection::DEFAULT_ACK_DELAY_EXPONENT)
      Wire::Packet.seal(header, packet_number: 0, packet_number_length: 1, payload:, keys:)
    end

    # A connection ID of `config.connection_id_length` bytes, from the
    # generator, that leads to nothing yet. With none found in
    # CONNECTION_ID_ATTEMPTS draws, as with zero-length connection IDs,
    # which only one connection can have, the Endpoint can take no more
    # connections: Error::StateError. A generator that gives another length
    # is misused: Error::Usage.
    private def new_connection_id
      length = @config.connection_id_length
      CONNECTION_ID_ATTEMPTS.times do
        id = @connection_ids.generate(length)
        raise Error::Usage, "the connection ID generator gave #{id.bytesize} bytes, not #{length}" unless id.bytesize == length
        return id unless @connections.key?(id) || @handles.key?(id)
      end
      raise Error::StateError, "no connection ID of #{@config.connection_id_length} bytes is free for another connection"
    end

    # A connection ID that leads to `connection`, and its stateless reset
    # token.
    private def issue_connection_id(connection)
      id = new_connection_id
      @connections[id] = connection
      [id, StatelessReset.token(key: @stateless_reset_key, connection_id: id)]
    end

    private def pending!(handle)
      return if @handles[handle.destination_connection_id].equal?(handle)
      raise Error::StateError, "the offer has been decided on or has expired"
    end

    private def forget(handle)
      @handles.delete(handle.destination_connection_id)
      @buffered -= handle.buffered
    end

    # RFC 9000 "Version Negotiation": a packet of a version not supported,
    # in a datagram large enough to start a connection, is answered with
    # the versions that are.
    private def negotiate(packet, datagram, from, to)
      return Route::Drop.new(reason: :too_short) if datagram.bytesize < Connection::MIN_INITIAL_DATAGRAM
      Route::Respond.new(transmit: transmit(packet.negotiation(@config.versions.map(&:number)).encode, from, to))
    end

    # RFC 9000 "Stateless Reset": a short header packet of no connection is
    # answered with a reset whose token comes from its connection ID, when
    # the address has resets left.
    private def reset(dcid, datagram, from, to, now)
      length = [datagram.bytesize - 1, MAX_RESET_LENGTH].min
      return Route::Drop.new(reason: :unknown_connection_id) if length < StatelessReset::MIN_LENGTH
      return Route::Drop.new(reason: :reset_rate_limited) unless take_reset(from, now)
      token = StatelessReset.token(key: @stateless_reset_key, connection_id: dcid)
      Route::Respond.new(transmit: transmit(StatelessReset.packet(token:, length:, random: @random), from, to))
    end

    # Takes a reset from the bucket of `address`, which goes to the end of
    # the table as the most recently used, and from the bucket of all.
    private def take_reset(address, now)
      tokens, at = @resets.delete(address) || [RESET_BURST, now]
      @resets.shift if @resets.size >= RESET_ADDRESSES
      tokens = [tokens + (now - at) * RESET_RATE, RESET_BURST].min
      total = [@reset_total + (now - @reset_total_at) * RESET_TOTAL_RATE, RESET_TOTAL_BURST].min
      taken = tokens >= 1 && total >= 1
      @resets[address] = [taken ? tokens - 1 : tokens, now]
      @reset_total = taken ? total - 1 : total
      @reset_total_at = now
      taken
    end

    private def transmit(payload, destination, source) = Transmit.new(payload:, destination:, source:, ecn: :not_ect, segment_size: nil)

    # The wall clock at `now`.
    private def wall_clock(now) = @time + (now - @created_at)

    private def instance_variables_to_inspect = %i[@config]
  end
end
