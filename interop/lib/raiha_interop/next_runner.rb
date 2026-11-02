# frozen_string_literal: true

require_relative "next_client"
require_relative "next_http3_client"
require_relative "next_http3_server"
require_relative "next_server"

module RaihaInterop
  # The entry point of the next release of raiha, which the image built
  # with RAIHA_IMPL=next runs: the testcases it takes in each role, by the
  # names the runner gives them there (multiplexing is a transfer to both,
  # keyupdate a transfer to the server), and the client or the server of
  # hq-interop for them, or of HTTP/3 for http3. Key updates come without
  # asking, after the first hundred packets.
  module NextRunner
    CLIENT_TESTCASES = %w[handshake transfer retry chacha20 keyupdate versionnegotiation resumption zerortt http3].freeze
    SERVER_TESTCASES = %w[handshake transfer retry chacha20 versionnegotiation resumption zerortt http3].freeze
    # What quic-interop-runner takes for a testcase not implemented.
    NOT_IMPLEMENTED = 127

    def self.run(env:, role:, testcase:, logger:)
      testcases = role == "server" ? SERVER_TESTCASES : CLIENT_TESTCASES
      unless testcases.include?(testcase)
        logger.puts("raiha-interop next: unsupported testcase=#{testcase} role=#{role}")
        return NOT_IMPLEMENTED
      end
      runner = if testcase == "http3"
        role == "server" ? NextHTTP3Server : NextHTTP3Client
      else
        role == "server" ? NextServer : NextClient
      end
      runner.new(env:, testcase:, logger:).run
    end
  end
end
