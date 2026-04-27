# frozen_string_literal: true

require_relative "protocol/connection_id"
require_relative "protocol/version"
require_relative "wire/buffer"
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

    def initialize(supported_versions: Protocol::Version::SUPPORTED_VERSIONS)
      @connections = {} #: Hash[String, Raiha::Connection]
      @supported_versions = supported_versions
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
      version = datagram.byteslice(LONG_HEADER_VERSION_OFFSET, 4).unpack1("N")

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
      return nil unless connection

      connection.handle_packet(datagram, peer_address: peer_address, ecn: ecn)
      nil
    end

    private def dispatch_short_header(datagram, peer_address:, ecn:)
      # 1-RTT packets carry an opaque DCID without a length prefix; the
      # Demuxer does not yet know how to recover the boundary in that
      # frame, so an unmatched short-header packet is dropped here.
      # Stateless Reset emission will hook in at this point.
      nil
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
