# frozen_string_literal: true

require "ipaddr"

module Raiha::QUIC
  # What connections are set up with, one value for every connection of an
  # Endpoint and shareable between Ractors: the transport parameters this
  # end sends, named as RFC 9000 names them, and settings of this
  # implementation that never go on the wire. Certificates and keys, the
  # random source and the tracer are not here, since they cannot be shared
  # between Ractors; the TLS settings are in the TLS layer's Config.
  #
  # Times are Float seconds. initial_max_streams_uni is 100, as quic-go's
  # and quiche's are: HTTP/3 needs three of the peer's streams going one
  # way, and the peer's streams of reserved or unknown types are not to
  # leave it short of them. max_datagram_frame_size nil (or 0) is no
  # DATAGRAM frames; RFC 9221 suggests 65535 to have them. max_udp_payload_size
  # is what this end can receive, and initial_max_datagram_size what it
  # sends before a path is probed: two things, however alike the names.
  # enable_pmtud probes each path for larger datagrams (RFC 8899
  # "Datagram Packetization Layer Path MTU Discovery"); a probe that IP
  # fragments on the way would pass for one that fits, so the I/O layer
  # must keep IP from fragmenting what it sends, as Runtime::UDP does
  # where it can, or the application sets it false.
  #
  # congestion_control is the class of the algorithm each path makes its
  # controller from, or its name in Congestion::ALGORITHMS; initial_window
  # turns a maximum datagram size into the initial window and must be
  # shareable, as a lambda made by Ractor.shareable_lambda. startup is the
  # class that wraps the controller while the connection starts, nil for
  # the controller's own slow start, and pacing_granularity the seconds
  # between the wake-ups of pacing. max_transmit_size is the most bytes a
  # Transmit carries, datagrams of one size but the last for GSO, nil for
  # a datagram each, as an I/O layer that sends Transmit#payload as it is
  # needs. fast_convergence is CUBIC's (RFC 9438
  # "Fast Convergence"), and beta_ecn the factor the window is multiplied by
  # when an ECN-CE mark alone starts a recovery period, nil for the
  # algorithm's own factor of a loss.
  #
  # retry_token_key and stateless_reset_key are the secrets an Endpoint
  # makes its Retry tokens and stateless reset tokens with; every worker
  # serving the same connections, in Ractors or processes, must have the
  # same ones.
  # Left nil, an Endpoint draws its own, which only one process can use.
  # inspect does not show them.
  #
  # preferred_address is the address a server offers its clients to move
  # to once the handshake is confirmed (RFC 9000 "Preferred Address"),
  # `{ipv4: [host, port], ipv6: [host, port]}` with either or both, nil
  # for none. address_families are those of the addresses this end can
  # send to, :ipv4 and :ipv6, which a client chooses the server's
  # preferred address from. ecn_address_families are those whose paths
  # use ECN; a path to an address of another starts with ECN failed, its
  # packets Not-ECT, as where the socket can neither mark nor read the
  # codepoint (Runtime::UDP.ecn, OpenBSD's IPv4).
  class Config < Data.define(
    :max_idle_timeout, :max_udp_payload_size,
    :initial_max_data, :initial_max_stream_data_bidi_local, :initial_max_stream_data_bidi_remote, :initial_max_stream_data_uni,
    :initial_max_streams_bidi, :initial_max_streams_uni,
    :max_ack_delay, :ack_delay_exponent, :active_connection_id_limit, :disable_active_migration, :max_datagram_frame_size,
    :versions, :connection_id_length, :initial_max_datagram_size, :enable_pmtud,
    :max_stream_receive_window, :max_receive_window, :max_send_buffer,
    :congestion_control, :initial_window, :startup, :pacing_granularity, :max_transmit_size, :fast_convergence, :beta_ecn,
    :retry_token_key, :stateless_reset_key, :preferred_address, :address_families, :ecn_address_families
  )
    include Raiha::TLS::MaskedInspect

    DEFAULT_CONGESTION_CONTROL = Congestion::Cubic
    # RFC 9002 "Initial and Minimum Congestion Window". Made shareable here,
    # where self is the class.
    DEFAULT_INITIAL_WINDOW = Ractor.make_shareable(->(max_datagram_size) { [10 * max_datagram_size, [14_720, 2 * max_datagram_size].max].min })

    # The fewest bytes a key of an Endpoint's tokens has: HMAC-SHA256's.
    MIN_KEY_LENGTH = 32

    ADDRESS_FAMILIES = %i[ipv4 ipv6].freeze

    TRANSPORT_PARAMETERS = %i[
      max_idle_timeout max_udp_payload_size
      initial_max_data initial_max_stream_data_bidi_local initial_max_stream_data_bidi_remote initial_max_stream_data_uni
      initial_max_streams_bidi initial_max_streams_uni
      max_ack_delay ack_delay_exponent active_connection_id_limit disable_active_migration max_datagram_frame_size
    ].freeze

    # Beside the rules of the transport parameters themselves: the versions
    # are supported ones, the connection IDs this end issues are 0 to 20
    # bytes, a datagram is 1200 bytes at least (RFC 9000 "Datagram Size"),
    # and the receive windows can grow from the initial ones: the stream
    # window to each initial stream limit, and the connection window to the
    # initial limit and to 1.5 times the stream window. The initial window
    # is the minimum of two datagrams at least, pacing wakes up after some
    # time, a Transmit carries something, and beta_ecn shrinks the window. A
    # key has MIN_KEY_LENGTH bytes at least. A preferred address has an
    # address of its family and a port, and comes with connection IDs that
    # are not zero-length, as a server that sends with none offers none (RFC
    # 9000 "Preferred Address"); the address families are some of
    # ADDRESS_FAMILIES.
    def initialize(
      max_idle_timeout: 30.0, max_udp_payload_size: 65_527,
      initial_max_data: 768 * 1024, initial_max_stream_data_bidi_local: 512 * 1024,
      initial_max_stream_data_bidi_remote: 512 * 1024, initial_max_stream_data_uni: 512 * 1024,
      initial_max_streams_bidi: 100, initial_max_streams_uni: 100,
      max_ack_delay: 0.025, ack_delay_exponent: 3, active_connection_id_limit: 8, disable_active_migration: false,
      max_datagram_frame_size: nil,
      versions: [Version::V1], connection_id_length: 8, initial_max_datagram_size: 1200, enable_pmtud: true,
      max_stream_receive_window: 6 * 1024 * 1024, max_receive_window: 15 * 1024 * 1024, max_send_buffer: 15 * 1024 * 1024,
      congestion_control: DEFAULT_CONGESTION_CONTROL, initial_window: DEFAULT_INITIAL_WINDOW, startup: nil, pacing_granularity: 0.001,
      max_transmit_size: nil, fast_convergence: true, beta_ecn: nil, retry_token_key: nil, stateless_reset_key: nil,
      preferred_address: nil, address_families: ADDRESS_FAMILIES, ecn_address_families: ADDRESS_FAMILIES
    )
      TransportParameters.new(
        max_idle_timeout:, max_udp_payload_size:, initial_max_data:, initial_max_stream_data_bidi_local:,
        initial_max_stream_data_bidi_remote:, initial_max_stream_data_uni:, initial_max_streams_bidi:, initial_max_streams_uni:,
        max_ack_delay:, ack_delay_exponent:, active_connection_id_limit:, disable_active_migration:,
        max_datagram_frame_size: max_datagram_frame_size || 0
      )
      raise ArgumentError, "no versions" if versions.empty?
      versions.each { |version| raise ArgumentError, "#{version.inspect} is no supported version" unless Version::SUPPORTED.include?(version) }
      unless connection_id_length.between?(0, Wire::CONNECTION_ID_MAX_LENGTH)
        raise ArgumentError, "connection_id_length #{connection_id_length} is not 0 to 20"
      end
      raise ArgumentError, "initial_max_datagram_size #{initial_max_datagram_size} is under 1200" if initial_max_datagram_size < 1200
      [initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni].each do |initial|
        raise ArgumentError, "max_stream_receive_window #{max_stream_receive_window} is under #{initial}" if max_stream_receive_window < initial
      end
      raise ArgumentError, "max_receive_window #{max_receive_window} is under initial_max_data" if max_receive_window < initial_max_data
      if max_receive_window < max_stream_receive_window * 1.5
        raise ArgumentError, "max_receive_window #{max_receive_window} is under 1.5 times max_stream_receive_window"
      end
      raise ArgumentError, "max_send_buffer #{max_send_buffer} is not positive" unless max_send_buffer.positive?
      congestion_control = Congestion.resolve(congestion_control)
      window = initial_window.call(initial_max_datagram_size)
      unless window.is_a?(Integer) && window >= 2 * initial_max_datagram_size
        raise ArgumentError, "an initial window of #{window.inspect} for #{initial_max_datagram_size}-byte datagrams is under two of them"
      end
      case startup
      when nil, Class then nil
      else raise ArgumentError, "startup is a class or nil"
      end
      raise ArgumentError, "pacing_granularity #{pacing_granularity} is not positive" unless pacing_granularity.positive?
      raise ArgumentError, "max_transmit_size #{max_transmit_size} is not positive" if max_transmit_size && !max_transmit_size.positive?
      raise ArgumentError, "beta_ecn #{beta_ecn} is not between 0 and 1" if beta_ecn && !(beta_ecn > 0 && beta_ecn < 1)
      { retry_token_key:, stateless_reset_key: }.each do |name, key|
        raise ArgumentError, "#{name} is under #{MIN_KEY_LENGTH} bytes" if key && key.bytesize < MIN_KEY_LENGTH
      end
      check_preferred_address(preferred_address, connection_id_length) if preferred_address
      if address_families.empty? || !(address_families - ADDRESS_FAMILIES).empty?
        raise ArgumentError, "address_families #{address_families.inspect} are not some of #{ADDRESS_FAMILIES.inspect}"
      end
      # None is ECN on no path at all.
      unless (ecn_address_families - ADDRESS_FAMILIES).empty?
        raise ArgumentError, "ecn_address_families #{ecn_address_families.inspect} are not of #{ADDRESS_FAMILIES.inspect}"
      end
      retry_token_key = retry_token_key&.b&.freeze
      stateless_reset_key = stateless_reset_key&.b&.freeze
      # A copy, so that making it shareable does not freeze the caller's.
      versions = Ractor.make_shareable(versions, copy: true)
      preferred_address = Ractor.make_shareable(preferred_address, copy: true)
      address_families = Ractor.make_shareable(address_families, copy: true)
      ecn_address_families = Ractor.make_shareable(ecn_address_families, copy: true)
      begin
        initial_window = Ractor.make_shareable(initial_window, copy: true)
      rescue TypeError, Ractor::Error => error
        raise ArgumentError, "initial_window cannot be shared between Ractors (#{error.message}); make it with Ractor.shareable_lambda"
      end
      super
    end

    def masked_members = %i[retry_token_key stateless_reset_key]

    private def check_preferred_address(preferred_address, connection_id_length)
      raise ArgumentError, "a preferred address with zero-length connection IDs" if connection_id_length.zero?
      if preferred_address.empty? || !(preferred_address.keys - ADDRESS_FAMILIES).empty?
        raise ArgumentError, "a preferred address of #{preferred_address.keys.inspect}, not some of #{ADDRESS_FAMILIES.inspect}"
      end
      preferred_address.each do |family, (host, port)|
        address = IPAddr.new(host)
        raise ArgumentError, "#{host} is no #{family} address" unless family == :ipv4 ? address.ipv4? : address.ipv6?
        raise ArgumentError, "a preferred address with port #{port}" unless port.between?(1, 65_535)
      end
    end

    # The transport parameters a connection with these settings sends, with
    # its connection IDs and, for a server, its token and preferred address.
    def transport_parameters(
      initial_source_connection_id:, original_destination_connection_id: nil, retry_source_connection_id: nil,
      stateless_reset_token: nil, preferred_address: nil
    )
      parameters = to_h.slice(*TRANSPORT_PARAMETERS).merge(max_datagram_frame_size: max_datagram_frame_size || 0)
      TransportParameters.new(
        **parameters, initial_source_connection_id:, original_destination_connection_id:, retry_source_connection_id:,
        stateless_reset_token:, preferred_address:
      )
    end
  end
end
