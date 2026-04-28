# frozen_string_literal: true

require "securerandom"

require_relative "protocol/connection_id"
require_relative "protocol/version"
require_relative "retry_token"
require_relative "stateless_reset"
require_relative "wire/buffer"
require_relative "wire/long_header"
require_relative "wire/retry"
require_relative "wire/version_negotiation"

module Raiha::Quic
  # Demultiplexes inbound UDP datagrams against a registry of active
  # Connection objects keyed by their server-chosen destination
  # connection ID. The Demuxer also produces stateless responses
  # (Version Negotiation today; Stateless Reset and Retry to follow)
  # that need to be emitted before — or instead of — handing the
  # datagram to a Connection.
  #
  # Datagrams are routed by extracting the Destination Connection ID
  # from the first byte / long-header form. Application code is still
  # responsible for creating new Connections (and registering them
  # here) when an Initial arrives for a CID we don't yet know about.
  class Demuxer
    LONG_HEADER_VERSION_OFFSET = 1
    LONG_HEADER_DCID_OFFSET = 5

    def initialize(supported_versions: Protocol::Version::SUPPORTED_VERSIONS,
                   stateless_reset_key: nil,
                   retry_key: nil,
                   require_retry: false,
                   server_connection_id_length: 8)
      @connections = {} #: Hash[String, Raiha::Connection]
      @supported_versions = supported_versions
      @stateless_reset_key = stateless_reset_key
      @retry_key = retry_key
      @require_retry = require_retry
      @server_connection_id_length = server_connection_id_length
      @validated_initials = {} #: Hash[String, { original_dcid: String }]
    end

    def register(connection_id, connection)
      @connections[connection_id_key(connection_id)] = connection
    end

    def unregister(connection_id)
      @connections.delete(connection_id_key(connection_id))
    end

    def registered?(connection_id)
      @connections.key?(connection_id_key(connection_id))
    end

    # Inspect `datagram` and either route it to a registered Connection
    # or return a stateless response datagram (currently only Version
    # Negotiation). Returns the raw response bytes the caller must put
    # back on the wire, or nil when nothing needs to be sent (the
    # datagram was either delivered, malformed, or unmatched).
    def dispatch(datagram, peer_address: nil, ecn: :not_ect)
      return nil if datagram.bytesize < LONG_HEADER_DCID_OFFSET

      first_byte = datagram.getbyte(0)
      return nil unless first_byte

      if (first_byte & 0x80) != 0
        dispatch_long_header(datagram, peer_address: peer_address, ecn: ecn)
      else
        dispatch_short_header(datagram, peer_address: peer_address, ecn: ecn)
      end
    end

    private def dispatch_long_header(datagram, peer_address:, ecn:)
      version = datagram.byteslice(LONG_HEADER_VERSION_OFFSET, 4).unpack1("N") # steep:ignore

      # RFC 9000 §6: a VN packet from the server uses Version=0; an
      # incoming datagram with Version=0 is from the client side and
      # should be handled differently — Demuxer is server-facing here
      # so treat it as malformed and drop.
      return nil if version == Protocol::Version::VERSION_NEGOTIATION

      unless @supported_versions.include?(version)
        return build_version_negotiation_response(datagram)
      end

      dcid = read_long_header_dcid(datagram)
      return nil unless dcid

      connection = @connections[connection_id_key(dcid)]
      if connection
        connection.handle_packet(datagram, peer_address: peer_address, ecn: ecn)
        return nil
      end

      maybe_handle_initial(datagram, version: version, peer_address: peer_address)
    end

    # RFC 9000 §17.2.5: when an Initial arrives for an unregistered
    # DCID, optionally answer with a Retry packet that forces the
    # client to bounce a server-issued token off its address before we
    # commit any state. The token binds the original DCID + peer
    # address; the second Initial echoes it and we recover the ODCID
    # to plug into the Connection that the application will create.
    private def maybe_handle_initial(datagram, version:, peer_address:)
      return nil unless @require_retry && @retry_key

      header = parse_initial_header(datagram, version: version)
      return nil unless header

      peer_bytes = peer_address_bytes(peer_address)
      return nil unless peer_bytes

      if header[:token].empty?
        return build_retry_response(
          version: version,
          original_dcid: header[:dcid],
          client_scid: header[:scid],
          peer_bytes: peer_bytes
        )
      end

      odcid = RetryToken.verify(
        retry_key: @retry_key, # steep:ignore
        token: header[:token],
        peer_address_bytes: peer_bytes
      )
      return nil unless odcid

      # Stash the validated ODCID so the application's connection
      # factory can read it back when creating the Connection.
      @validated_initials[connection_id_key(header[:dcid])] = { original_dcid: odcid }
      nil
    end

    public def validated_original_dcid(connection_id)
      entry = @validated_initials[connection_id_key(connection_id)]
      entry && entry[:original_dcid]
    end

    private def dispatch_short_header(datagram, peer_address:, ecn:)
      # 1-RTT packets do not encode the DCID length on the wire — the
      # server is expected to know the length it issued. The demuxer
      # is configured with a fixed length (RFC 9000 §5.1 explicitly
      # encourages servers to use one) and pulls the DCID off the
      # front. A registered Connection consumes the datagram; an
      # unrecognized DCID with a configured stateless_reset_key
      # produces a Stateless Reset (RFC 9000 §10.3.1).
      return nil if datagram.bytesize < 1 + @server_connection_id_length

      dcid_bytes = datagram.byteslice(1, @server_connection_id_length)
      return nil unless dcid_bytes

      connection = @connections[connection_id_key(dcid_bytes)]
      if connection
        connection.handle_packet(datagram, peer_address: peer_address, ecn: ecn)
        return nil
      end

      build_stateless_reset_response(dcid_bytes, datagram.bytesize)
    end

    private def parse_initial_header(datagram, version:)
      buf = Wire::Buffer.new(datagram)
      first_byte = buf.read_uint8
      return nil unless first_byte
      packet_type = (first_byte & 0x30) >> 4
      return nil unless packet_type == Wire::LongHeader::PacketType::INITIAL

      buf.read_uint32 # version (already extracted)
      dcid_length = buf.read_uint8
      return nil unless dcid_length
      dcid = buf.read(dcid_length)
      scid_length = buf.read_uint8
      return nil unless scid_length
      scid = buf.read(scid_length)
      token_length = buf.read_varint
      return nil unless token_length
      token = token_length > 0 ? buf.read(token_length) : "".b

      { dcid: dcid, scid: scid, token: token }
    end

    private def peer_address_bytes(peer_address)
      case peer_address
      when nil then nil
      when String then peer_address
      when Array then peer_address.map(&:to_s).join(":")
      else peer_address.to_s
      end
    end

    private def build_retry_response(version:, original_dcid:, client_scid:, peer_bytes:)
      # The Retry packet's SCID becomes the client's new DCID. We
      # generate a fresh CID here so the routing key the client uses
      # in its second Initial differs from the ODCID — that is the
      # whole point of address validation.
      retry_scid = SecureRandom.random_bytes(@server_connection_id_length)
      token = RetryToken.mint(
        retry_key: @retry_key, # steep:ignore
        peer_address_bytes: peer_bytes,
        original_destination_connection_id: original_dcid
      )

      Wire::Retry.build(
        source_connection_id: retry_scid,
        destination_connection_id: client_scid,
        original_destination_connection_id: original_dcid,
        retry_token: token,
        version: version
      )
    end

    # RFC 9000 §10.3.1: build a Stateless Reset whose trailing 16
    # bytes are HMAC(stateless_reset_key, DCID). The packet must be
    # smaller than the triggering datagram so the peer cannot use it
    # to inflate traffic; we simply mirror the incoming size minus
    # one byte.
    private def build_stateless_reset_response(dcid_bytes, incoming_size)
      return nil unless @stateless_reset_key

      token = StatelessReset.derive_token(@stateless_reset_key, dcid_bytes) # steep:ignore
      reset_size = [incoming_size - 1, StatelessReset::MIN_PACKET_LENGTH].max
      StatelessReset.build(token, min_size: reset_size)
    end

    # RFC 9000 §6.1: the VN response swaps the SCID and DCID from the
    # triggering packet. The list of supported versions is whatever
    # the demuxer was configured with.
    private def build_version_negotiation_response(datagram)
      buf = Wire::Buffer.new(datagram)
      buf.read_uint8 # first byte
      buf.read_uint32 # triggering version
      dcid_length = buf.read_uint8
      dcid_bytes = buf.read(dcid_length)
      scid_length = buf.read_uint8
      scid_bytes = buf.read(scid_length)

      Wire::VersionNegotiation.build(
        src_connection_id: dcid_bytes,
        dest_connection_id: scid_bytes,
        supported_versions: @supported_versions
      )
    end

    private def read_long_header_dcid(datagram)
      dcid_length = datagram.getbyte(LONG_HEADER_DCID_OFFSET)
      return nil unless dcid_length
      return nil if datagram.bytesize < LONG_HEADER_DCID_OFFSET + 1 + dcid_length

      datagram.byteslice(LONG_HEADER_DCID_OFFSET + 1, dcid_length)
    end

    private def connection_id_key(cid)
      case cid
      when Protocol::ConnectionID then cid.serialize
      else cid
      end
    end
  end
end
