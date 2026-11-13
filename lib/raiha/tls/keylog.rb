# frozen_string_literal: true

module Raiha::Next::TLS
  # Lines of the SSLKEYLOGFILE format (RFC 9850 "The SSLKEYLOGFILE Format
  # for TLS") for the `keylog:` of a Machine: a label, the ClientHello
  # random and a traffic secret, in hex. Only the traffic secrets are
  # written; the exporter secret is not, since it is not needed to decrypt
  # and would give away every exporter value.
  #
  # RFC 9850 forbids using this in production. Nothing turns it on but
  # code that passes `keylog:`; SSLKEYLOGFILE is not read.
  module Keylog
    LABELS = {
      client_early_traffic: "CLIENT_EARLY_TRAFFIC_SECRET",
      client_handshake_traffic: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
      server_handshake_traffic: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
      client_application_traffic: "CLIENT_TRAFFIC_SECRET_0",
      server_application_traffic: "SERVER_TRAFFIC_SECRET_0"
    }.freeze #: Hash[Symbol, String]

    # The line for the secret KeySchedule names `name`.
    def self.line(name, client_random, secret)
      "#{LABELS.fetch(name)} #{client_random.unpack1("H*")} #{secret.unpack1("H*")}\n"
    end

    # A keylog to give a Machine: `path` opened for appending and readable by
    # its owner only, even when it was there already.
    class File
      def initialize(path)
        @io = ::File.open(path, ::File::WRONLY | ::File::APPEND | ::File::CREAT, 0o600)
        @io.chmod(0o600)
        @io.sync = true
      end

      def write(line) = @io.write(line)

      def close = @io.close
    end
  end
end
