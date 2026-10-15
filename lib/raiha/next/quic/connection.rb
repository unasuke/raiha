# frozen_string_literal: true

module Raiha::Next::QUIC
  # One QUIC connection, sans-IO (250 "sans-IO core — Connection"): it is
  # given datagrams with `receive` and the time with `handle_timeout`, and
  # hands back the datagrams to send with `each_transmit` and what happened
  # with `each_event`. It never reads a clock; `now:` is the monotonic
  # clock in Float seconds, and TLS's wall clock is `time:`, given once when
  # the connection is made, moved on by the monotonic clock since.
  #
  # A connection knows only itself: an Endpoint finds it by connection ID.
  class Connection
    # The encryption levels, in the order their packets go in a datagram.
    LEVELS = %i[initial zero_rtt handshake one_rtt].freeze
    # The packet number space of each level.
    SPACES = { initial: :initial, zero_rtt: :application_data, handshake: :handshake, one_rtt: :application_data }.freeze
    # RFC 9000 "Datagram Size": a datagram with an Initial packet in it
    # from a client, or with an ack-eliciting one from a server, is padded
    # to this.
    MIN_INITIAL_DATAGRAM = 1200
    # The length of a client's first Destination Connection ID (RFC 9000
    # "Negotiating Connection IDs": 8 bytes at least).
    INITIAL_DCID_LENGTH = 8
    # The ACK Delay exponent before the peer's is known, and for the ACK
    # frames of Initial and Handshake packets.
    DEFAULT_ACK_DELAY_EXPONENT = 3
    # Bytes a long header adds to its connection IDs and token, with a
    # 2-byte Length and a 4-byte packet number at most, and the AEAD tag.
    LONG_HEADER_OVERHEAD = 1 + 4 + 1 + 1 + 2 + 4 + 16
    SHORT_HEADER_OVERHEAD = 1 + 4 + 16

    # A packet put together, not yet protected.
    Pending = Data.define(:level, :header, :packet_number, :packet_number_length, :frames, :duties)

    attr_reader :role, :path

    # A client connection to `remote` ([host, port]), with its first
    # Initial packet waiting to be sent. `tls_config` has the QUIC profile.
    def self.client(config:, tls_config:, keyring:, server_name:, remote:, time:, now:, tracer: nil, keylog: nil)
      new(role: :client, config:, now:, time:, remote:, tracer:, random: keyring.random) do |connection, parameters|
        TLSBinding.client(connection:, config: tls_config, keyring:, server_name:, transport_parameters: parameters, time:, keylog:)
      end
    end

    # A server connection, which takes the client's first Initial packet as
    # it comes and starts TLS then, when the client's first Destination
    # Connection ID, which its transport parameters carry, is known.
    def self.server(config:, tls_config:, keyring:, time:, now:, tracer: nil, keylog: nil)
      new(role: :server, config:, now:, time:, remote: nil, tracer:, random: keyring.random) do |connection, parameters|
        TLSBinding.server(connection:, config: tls_config, keyring:, transport_parameters: parameters, time:, keylog:)
      end
    end

    private_class_method :new

    def initialize(role:, config:, now:, time:, remote:, tracer:, random:, &start)
      @role = role
      @config = config
      @version = config.versions.fetch(0)
      @created_at = now
      @time = time
      @remote = remote
      @tracer = tracer
      @path = Path.new(config:, tracer:)
      @recovery = Recovery.new(role:, config:, path: @path, random:, now:, tracer:)
      @protection = PacketProtection.new(role:, version: @version)
      @events = [] #: Array[Event::t]
      @source_connection_id = random.bytes(config.connection_id_length).b
      @peer_parameters = nil #: TransportParameters?
      @handshake_complete = false
      @peer_connection_id_adopted = false
      @start_binding = start
      @binding = nil #: TLSBinding?
      if role == :client
        @destination_connection_id = random.bytes(INITIAL_DCID_LENGTH).b
        @protection.install_initial(@destination_connection_id)
        @binding = start.call(self, config.transport_parameters(initial_source_connection_id: @source_connection_id))
      else
        @destination_connection_id = "".b
      end
    end

    # Whether TLS has completed the handshake on this end.
    def handshake_complete? = @handshake_complete

    def next_event = @events.shift

    def each_event
      while (event = @events.shift)
        yield event
      end
    end

    # Takes a datagram that came from `from` with the ECN codepoint `ecn`.
    # The packets coalesced in it are handled one after another.
    def receive(datagram, from:, to: nil, ecn: :not_ect, now:)
      offset = 0
      while offset < datagram.bytesize
        packet = parse_packet(datagram, offset) or break
        receive_packet(packet, from:, ecn:, now:)
        offset = packet.end_offset
      end
    end

    # Each datagram there is to send now.
    def each_transmit(now:)
      while (datagram = next_datagram(now))
        yield Transmit.new(payload: datagram, destination: remote, source: nil, ecn: @path.ecn, segment_size: nil)
      end
    end

    def transmits(now:)
      transmits = [] #: Array[Transmit]
      each_transmit(now:) { |transmit| transmits << transmit }
      transmits
    end

    def next_timeout = @recovery.next_timeout

    def handle_timeout(now:)
      outcome = @recovery.on_timeout(now:)
      Recovery::Duty.dispatch(outcome, to: self)
    end

    # TLSBinding::_Connection

    def install_keys(level, direction, secret:, suite:) = @protection.install(level, direction, secret:, suite:)

    def peer_transport_parameters(data)
      @peer_parameters = TransportParameters.decode(data, sender: @role == :client ? :server : :client)
    end

    def handshake_completed(event)
      @handshake_complete = true
      @events << Event::Connected.new(handshake: event)
    end

    def tls_failed(code, reason) = nil

    def tls_event(event) = @events << Event::TLSEvent.new(event:)

    # Recovery::Duty::_Owner

    def crypto_data_acked(duty) = binding.crypto_acked(duty)

    def crypto_data_lost(duty) = binding.crypto_lost(duty)

    def ack_frame_acked(duty) = @recovery.ack_frame_acknowledged(duty.space, largest: duty.largest)

    # Streams, flow control, connection IDs and tokens are not sent yet, so
    # their duties never come back.

    def stream_data_acked(duty) = nil
    def reset_stream_acked(duty) = nil
    def stream_data_lost(duty) = nil
    def reset_stream_lost(duty) = nil
    def stop_sending_lost(duty) = nil
    def max_data_lost(duty) = nil
    def max_stream_data_lost(duty) = nil
    def max_streams_lost(duty) = nil
    def data_blocked_lost(duty) = nil
    def stream_data_blocked_lost(duty) = nil
    def streams_blocked_lost(duty) = nil
    def new_connection_id_lost(duty) = nil
    def retire_connection_id_lost(duty) = nil
    def new_token_lost(duty) = nil
    def handshake_done_lost = nil

    private def remote = @remote || raise(Error::StateError, "no packet has come from the client yet")

    private def binding = @binding || raise(Error::StateError, "no Initial packet has come from the client yet")

    # The packet at `offset` in `datagram`, nil when there is none to take.
    # A header that does not read is dropped with the rest of the datagram
    # and nothing else: before its protection is off, anyone could have sent
    # it.
    private def parse_packet(datagram, offset)
      packet = Wire::Packet.parse(datagram, offset:, dcid_length: @source_connection_id.bytesize)
      packet if packet.is_a?(Wire::Packet::Parsed)
    rescue Wire::Malformed
      nil
    end

    private def receive_packet(packet, from:, ecn:, now:)
      header = packet.header
      level = header.type
      if @role == :server && header.is_a?(Wire::LongHeader) && level == :initial && @destination_connection_id.empty?
        accept_first_initial(header, from)
      end
      keys = @protection.read_keys(level) or return
      unmasked = packet.unmask(keys.header_protection, largest: @recovery.largest_received(level))
      payload = unmasked.open(keys.aead) or return
      frames = Wire::Frame.parse(payload, packet_type: level, ack_delay_exponent: peer_ack_delay_exponent(level))
      return unless @recovery.on_packet_received(packet_type: level, packet_number: unmasked.packet_number, ecn:,
        ack_eliciting: frames.any?(&:ack_eliciting?), now:)
      adopt_peer_connection_id(header) if @role == :client && header.is_a?(Wire::LongHeader)
      frames.each { |frame| receive_frame(level, frame, now) }
    end

    # The server learns from the client's first Initial its connection ID,
    # address and the Destination Connection ID its Initial keys come from.
    private def accept_first_initial(header, from)
      @remote = from
      @destination_connection_id = header.scid
      @protection.install_initial(header.dcid)
      parameters = @config.transport_parameters(initial_source_connection_id: @source_connection_id,
        original_destination_connection_id: header.dcid)
      @binding = @start_binding.call(self, parameters)
    end

    # A client takes the Source Connection ID of the server's first packet
    # as the Destination Connection ID of its own (RFC 9000 "Negotiating
    # Connection IDs").
    private def adopt_peer_connection_id(header)
      @destination_connection_id = header.scid unless @peer_connection_id_adopted
      @peer_connection_id_adopted = true
    end

    private def receive_frame(level, frame, now)
      case frame
      when Wire::Frame::Crypto then binding.receive_crypto(level, frame, time: tls_time(now))
      when Wire::Frame::Ack
        Recovery::Duty.dispatch(@recovery.on_ack_received(packet_type: level, ack: frame, now:), to: self)
      end
    end

    # The next datagram to send, nil when there is nothing. What elicits an
    # ACK goes only while the congestion window has room for a datagram
    # more.
    private def next_datagram(now)
      limit = @path.max_datagram_size
      eliciting = @path.bytes_in_flight + limit <= @path.congestion.window
      pending = [] #: Array[Pending]
      used = 0
      LEVELS.each do |level|
        next unless @protection.can_write?(level)
        header = header_for(level)
        room = limit - used - overhead(header)
        frames, duties = frames_for(level, room, eliciting, now)
        next if frames.empty?
        packet_number = @recovery.next_packet_number(level)
        length = @recovery.packet_number_length(level, packet_number)
        pending << Pending.new(level:, header:, packet_number:, packet_number_length: length, frames:, duties:)
        used += overhead(header) + Wire::Frame.encode(frames, ack_delay_exponent: own_ack_delay_exponent(level)).bytesize
      end
      return nil if pending.empty?
      seal(pending, now)
    end

    # The frames of `level` that fit in `room` bytes, and their duties: an
    # ACK when one is owed and the packet goes anyway, or is due, then
    # CRYPTO when frames that elicit an ACK may go.
    private def frames_for(level, room, eliciting, now)
      frames = [] #: Array[Wire::Frame::t]
      duties = [] #: Array[Recovery::Duty::t]
      space = SPACES.fetch(level)
      ack = @recovery.ack_frame(space, now:) if @recovery.ack_owed?(space) || @recovery.ack_due?(space, now:)
      room -= Wire::Frame.encode([ack], ack_delay_exponent: own_ack_delay_exponent(level)).bytesize if ack
      while eliciting && room.positive? && (frame, duty = binding.next_crypto_frame(level, room))
        frames << frame
        duties << duty
        room -= Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize
      end
      if ack && (frames.any? || @recovery.ack_due?(space, now:))
        frames.unshift(ack)
        duties.unshift(Recovery::Duty::Ack.new(space:, largest: ack.largest))
        @recovery.on_ack_sent(space, now:)
      end
      [frames, duties]
    end

    # Protects the packets of a datagram and records them as sent. The
    # last is padded to make the datagram MIN_INITIAL_DATAGRAM bytes when
    # it carries a client's Initial, and every packet so that header
    # protection has its sample.
    private def seal(pending, now)
      target = @role == :client && pending.any? { |packet| packet.level == :initial } ? MIN_INITIAL_DATAGRAM : 0
      payloads = pending.map do |packet|
        payload = Wire::Frame.encode(packet.frames, ack_delay_exponent: own_ack_delay_exponent(packet.level))
        short = Wire::Packet::SAMPLE_OFFSET - packet.packet_number_length - payload.bytesize
        short.positive? ? payload + "\0".b * short : payload
      end
      size = pending.each_with_index.sum { |packet, index| sealed_size(packet, payloads.fetch(index).bytesize) }
      payloads[-1] = payloads.fetch(-1) + "\0".b * (target - size) if target > size
      pending.each_with_index.map { |packet, index| protect(packet, payloads.fetch(index), now) }.join
    end

    private def protect(packet, payload, now)
      keys = @protection.write_keys(packet.level) or raise Error::StateError, "no keys to write #{packet.level}"
      sealed = Wire::Packet.seal(packet.header, packet_number: packet.packet_number, packet_number_length: packet.packet_number_length,
        payload:, keys:)
      ack_eliciting = packet.frames.any?(&:ack_eliciting?)
      in_flight = ack_eliciting || payload.bytesize > Wire::Frame.encode(packet.frames, ack_delay_exponent: 0).bytesize
      @recovery.on_packet_sent(packet_type: packet.level, packet_number: packet.packet_number, sent_bytes: sealed.bytesize,
        ack_eliciting:, in_flight:, duties: packet.duties, now:)
      sealed
    end

    private def header_for(level)
      case level
      when :one_rtt then Wire::ShortHeader.new(dcid: @destination_connection_id, key_phase: 0)
      else Wire::LongHeader.new(type: level, version: @version, dcid: @destination_connection_id, scid: @source_connection_id)
      end
    end

    private def overhead(header)
      case header
      when Wire::LongHeader
        LONG_HEADER_OVERHEAD + header.dcid.bytesize + header.scid.bytesize + Wire::Varint.size(header.token.bytesize) + header.token.bytesize
      else SHORT_HEADER_OVERHEAD + header.dcid.bytesize
      end
    end

    # The bytes of `packet` with a payload of `length` bytes, protected.
    private def sealed_size(packet, length)
      header = packet.header
      keys = @protection.write_keys(packet.level) or raise Error::StateError, "no keys to write #{packet.level}"
      body = packet.packet_number_length + length + keys.aead.tag_length
      case header
      when Wire::LongHeader
        1 + 4 + 1 + header.dcid.bytesize + 1 + header.scid.bytesize + Wire::Varint.size(header.token.bytesize) + header.token.bytesize +
          Wire::Varint.size(body) + body
      else 1 + header.dcid.bytesize + body
      end
    end

    private def own_ack_delay_exponent(level) = level == :one_rtt ? @config.ack_delay_exponent : DEFAULT_ACK_DELAY_EXPONENT

    private def peer_ack_delay_exponent(level)
      return DEFAULT_ACK_DELAY_EXPONENT unless level == :one_rtt
      @peer_parameters&.ack_delay_exponent || DEFAULT_ACK_DELAY_EXPONENT
    end

    # TLS's wall clock at `now`.
    private def tls_time(now) = @time + (now - @created_at)
  end
end
