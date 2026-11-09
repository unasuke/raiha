# frozen_string_literal: true

require "ipaddr"

module Raiha::Next::QUIC
  # The transport parameters of one end (RFC 9000 "Transport Parameter
  # Definitions", and max_datagram_frame_size of RFC 9221), as the
  # quic_transport_parameters extension carries them. The names are the
  # RFC's. Times are Float seconds, milliseconds on the wire. A parameter
  # left out has its default: max_idle_timeout 0 is no timeout,
  # max_datagram_frame_size 0 is no DATAGRAM frames, and the connection
  # IDs, the token and the preferred address are nil.
  class TransportParameters < Data.define(
    :original_destination_connection_id, :max_idle_timeout, :stateless_reset_token, :max_udp_payload_size,
    :initial_max_data, :initial_max_stream_data_bidi_local, :initial_max_stream_data_bidi_remote, :initial_max_stream_data_uni,
    :initial_max_streams_bidi, :initial_max_streams_uni,
    :ack_delay_exponent, :max_ack_delay, :disable_active_migration, :preferred_address, :active_connection_id_limit,
    :initial_source_connection_id, :retry_source_connection_id, :max_datagram_frame_size
  )
    IDS = {
      original_destination_connection_id: 0x00, max_idle_timeout: 0x01, stateless_reset_token: 0x02, max_udp_payload_size: 0x03,
      initial_max_data: 0x04, initial_max_stream_data_bidi_local: 0x05, initial_max_stream_data_bidi_remote: 0x06,
      initial_max_stream_data_uni: 0x07, initial_max_streams_bidi: 0x08, initial_max_streams_uni: 0x09,
      ack_delay_exponent: 0x0a, max_ack_delay: 0x0b, disable_active_migration: 0x0c, preferred_address: 0x0d,
      active_connection_id_limit: 0x0e, initial_source_connection_id: 0x0f, retry_source_connection_id: 0x10,
      max_datagram_frame_size: 0x20
    }.freeze #: Hash[Symbol, Integer]
    NAMES = IDS.invert.freeze #: Hash[Integer, Symbol]
    MILLISECONDS = %i[max_idle_timeout max_ack_delay].freeze
    CONNECTION_IDS = %i[original_destination_connection_id initial_source_connection_id retry_source_connection_id].freeze
    # A client that sends one of these breaks RFC 9000 "Transport Parameter
    # Definitions".
    SERVER_ONLY = %i[original_destination_connection_id stateless_reset_token preferred_address retry_source_connection_id].freeze
    MAX_STREAM_COUNT = 1 << 60
    STATELESS_RESET_TOKEN_LENGTH = 16

    # A server's preferred address (RFC 9000 "Preferred Address"): an IPv4
    # and an IPv6 address, each `[host, port]` or nil when the server
    # offers none of that family, and the connection ID and stateless reset
    # token for using it.
    class PreferredAddress < Data.define(:ipv4, :ipv6, :connection_id, :stateless_reset_token)
      def initialize(ipv4:, ipv6:, connection_id:, stateless_reset_token:)
        raise ArgumentError, "#{ipv4.inspect} is no IPv4 address" if ipv4 && !IPAddr.new(ipv4[0]).ipv4?
        raise ArgumentError, "#{ipv6.inspect} is no IPv6 address" if ipv6 && !IPAddr.new(ipv6[0]).ipv6?
        unless connection_id.bytesize.between?(1, Wire::CONNECTION_ID_MAX_LENGTH)
          raise ArgumentError, "the preferred address has a connection ID of #{connection_id.bytesize} bytes"
        end
        unless stateless_reset_token.bytesize == STATELESS_RESET_TOKEN_LENGTH
          raise ArgumentError, "a stateless reset token has 16 bytes, not #{stateless_reset_token.bytesize}"
        end
        super
      end

      def self.read(reader)
        ipv4 = address(reader.bytes(4), reader.u16)
        ipv6 = address(reader.bytes(16), reader.u16)
        new(ipv4:, ipv6:, connection_id: reader.bytes(reader.u8), stateless_reset_token: reader.bytes(STATELESS_RESET_TOKEN_LENGTH))
      end

      # All zeros, address and port, stand for no address of the family.
      private_class_method def self.address(bytes, port)
        return nil if port.zero? && bytes.bytes.all?(&:zero?)
        [IPAddr.new_ntoh(bytes).to_s, port]
      end

      def encode
        writer = Wire::Writer.new
        writer.bytes(ipv4 ? IPAddr.new(ipv4[0]).hton : "\0".b * 4).u16(ipv4 ? ipv4[1] : 0)
        writer.bytes(ipv6 ? IPAddr.new(ipv6[0]).hton : "\0".b * 16).u16(ipv6 ? ipv6[1] : 0)
        writer.u8(connection_id.bytesize).bytes(connection_id).bytes(stateless_reset_token).to_s
      end
    end

    # The rules of RFC 9000 "Transport Parameter Definitions" on the values.
    def initialize(
      original_destination_connection_id: nil, max_idle_timeout: 0.0, stateless_reset_token: nil, max_udp_payload_size: 65_527,
      initial_max_data: 0, initial_max_stream_data_bidi_local: 0, initial_max_stream_data_bidi_remote: 0, initial_max_stream_data_uni: 0,
      initial_max_streams_bidi: 0, initial_max_streams_uni: 0,
      ack_delay_exponent: 3, max_ack_delay: 0.025, disable_active_migration: false, preferred_address: nil, active_connection_id_limit: 2,
      initial_source_connection_id: nil, retry_source_connection_id: nil, max_datagram_frame_size: 0
    )
      integers = [
        max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent,
        active_connection_id_limit, max_datagram_frame_size, (max_idle_timeout * 1000).round
      ]
      integers.each { |value| raise ArgumentError, "#{value} is no varint" unless value.between?(0, Wire::Varint::MAX) }
      raise ArgumentError, "max_udp_payload_size #{max_udp_payload_size} is under 1200" if max_udp_payload_size < 1200
      raise ArgumentError, "ack_delay_exponent #{ack_delay_exponent} is over 20" if ack_delay_exponent > 20
      raise ArgumentError, "max_ack_delay #{max_ack_delay} is 2^14 milliseconds or more" if max_ack_delay * 1000 >= 1 << 14
      raise ArgumentError, "active_connection_id_limit #{active_connection_id_limit} is under 2" if active_connection_id_limit < 2
      [initial_max_streams_bidi, initial_max_streams_uni].each do |count|
        raise ArgumentError, "a stream count of #{count} is past 2^60" if count > MAX_STREAM_COUNT
      end
      [original_destination_connection_id, initial_source_connection_id, retry_source_connection_id].compact.each do |cid|
        raise ArgumentError, "a connection ID of #{cid.bytesize} bytes" if cid.bytesize > Wire::CONNECTION_ID_MAX_LENGTH
      end
      if stateless_reset_token && stateless_reset_token.bytesize != STATELESS_RESET_TOKEN_LENGTH
        raise ArgumentError, "a stateless reset token has 16 bytes, not #{stateless_reset_token.bytesize}"
      end
      # RFC 9000 "Preferred Address": a server that sends with zero-length
      # connection IDs offers no preferred address.
      raise ArgumentError, "a preferred address with zero-length connection IDs" if preferred_address && initial_source_connection_id&.empty?
      super
    end

    DEFAULTS = new.to_h.freeze

    # The parameters as the extension carries them, in the order of their
    # IDs, those at their defaults left out.
    def encode
      writer = Wire::Writer.new
      to_h.each { |name, value| TransportParameters.write(writer, name, value) unless value == DEFAULTS.fetch(name) }
      writer.to_s
    end

    # Writes the parameter `name` with `value`: its ID, length and value. A
    # flag has no value; it is there when true and left out when false, as
    # is a parameter whose value is nil.
    def self.write(writer, name, value)
      body =
        if value == true then ""
        elsif value.is_a?(String) then value
        elsif value.is_a?(PreferredAddress) then value.encode
        elsif value.is_a?(Float) then Wire::Varint.encode((value * 1000).round)
        elsif value.is_a?(Integer) then Wire::Varint.encode(value)
        else return writer
        end
      writer.varint(IDS.fetch(name)).varint(body.bytesize).bytes(body)
    end

    # The parameters a client may remember for 0-RTT.
    def remembered = RememberedTransportParameters.new(**to_h.slice(*RememberedTransportParameters.members)) # steep:ignore

    # The parameters in `bytes`, sent by `sender` (:client or :server).
    # Unknown parameters, the reserved ones for GREASE among them, are
    # ignored (RFC 9000 "Reserved Transport Parameters"). Anything else that
    # is not right raises Wire::Malformed with TRANSPORT_PARAMETER_ERROR: a
    # value against the rules, a parameter only a server sends coming from a
    # client, and a missing initial_source_connection_id, or a missing
    # original_destination_connection_id from a server (RFC 9000
    # "Authenticating Connection IDs"). So does any ID twice, unknown ones
    # too: a peer may not send one twice (RFC 9000 "Transport Parameters"),
    # and taking the first or the last would let two readers of the same
    # bytes disagree.
    def self.decode(bytes, sender:)
      reader = Wire::Reader.new(bytes)
      # @type var parameters: Hash[Symbol, Integer | Float | bool | String | PreferredAddress]
      parameters = {}
      seen = Set.new #: Set[Integer]
      until reader.eof?
        id = reader.varint
        value = reader.sub(reader.varint)
        raise Wire::Malformed, "transport parameter 0x#{id.to_s(16)} twice" unless seen.add?(id)
        name = NAMES[id] or next
        raise Wire::Malformed, "#{name} from a client" if sender == :client && SERVER_ONLY.include?(name)
        parameters[name] = read_value(name, value)
        raise Wire::Malformed, "#{name} has #{value.remaining} bytes past its value" unless value.eof?
      end
      raise Wire::Malformed, "no initial_source_connection_id" unless parameters.key?(:initial_source_connection_id)
      if sender == :server && !parameters.key?(:original_destination_connection_id)
        raise Wire::Malformed, "no original_destination_connection_id from the server"
      end
      new(**parameters)
    rescue ArgumentError, Wire::Malformed => error
      raise Wire::Malformed.new(error.message, code: ErrorCode::TRANSPORT_PARAMETER_ERROR)
    end

    private_class_method def self.read_value(name, value)
      case name
      when :disable_active_migration then true
      when :preferred_address then PreferredAddress.read(value)
      when :stateless_reset_token, *CONNECTION_IDS then value.rest
      when *MILLISECONDS then value.varint / 1000.0
      else value.varint
      end
    end

    # The quic_transport_parameters extension (RFC 9001 "QUIC Transport
    # Parameters Extension") for the TLS layer's Extension::Registry. It
    # keeps the bytes that came: decoding them is the QUIC binding's, which
    # closes with TRANSPORT_PARAMETER_ERROR rather than with a TLS alert.
    # Registered, it lets TLS refuse the extension in any message but
    # ClientHello and EncryptedExtensions.
    module Extension
      TYPE = 0x39
      CODECS = {
        client_hello: Raiha::Next::TLS::Extension::Opaque::Parser.new(type: TYPE),
        encrypted_extensions: Raiha::Next::TLS::Extension::Opaque::Parser.new(type: TYPE)
      }.freeze
    end
  end
end
