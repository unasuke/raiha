# frozen_string_literal: true

require_relative "verifier"

module Raiha::TLS
  # The normal form of server_name at the edges of a handshake: ASCII
  # lowercase without a trailing dot. ClientHelloInfo, HandshakeComplete,
  # certificate selection and RFC 9525 matching all see this form.
  module ServerName
    MAX_LENGTH = 253
    LABEL = /\A[a-z0-9-]{1,63}\z/

    # The SNI to send and the name to match the certificate against, from
    # what the application asked for. An IP address literal is matched but
    # never sent as SNI (RFC 6066 "Server Name Indication"). A name that is not
    # an ASCII host name (U-labels included: pass A-labels) is an
    # ArgumentError.
    def self.for_client(name)
      return [nil, name] if Verifier::HostName.ip_address(name)
      normal = normalize(name) or raise ArgumentError, "#{name.inspect} is not an ASCII host name"
      [normal, normal]
    end

    # The peer's host_name in normal form, or nil and why it was ignored:
    # :ip_literal or :invalid_syntax. RFC 6066 lets a server go on without a
    # name it does not recognize, which is kinder to clients that send an
    # address or a trailing dot than failing.
    def self.for_server(host_name)
      return [nil, :ip_literal] if Verifier::HostName.ip_address(host_name)
      normal = normalize(host_name)
      normal ? [normal, nil] : [nil, :invalid_syntax]
    end

    # One trailing dot is dropped: RFC 9525 treats the two as the same name.
    def self.normalize(name)
      return nil unless name.ascii_only?
      normal = name.downcase.delete_suffix(".")
      return nil if normal.empty? || normal.bytesize > MAX_LENGTH
      normal.split(".", -1).all? { |label| label.match?(LABEL) } ? normal : nil
    end
  end
end
