# frozen_string_literal: true

require_relative "client"
require_relative "http3_client"
require_relative "http3_server"
require_relative "server"

module RaihaInterop
  # Top-level entry point used by interop/bin/raiha-interop. Reads the
  # role and the testcase from the quic-interop-runner environment
  # variables, and runs the client or the server of hq-interop for the
  # testcases it takes in that role, by the names the runner gives them
  # there, or of HTTP/3 for http3. Key updates come without asking, after
  # the first hundred packets. Returns an integer exit status.
  #
  # The runner gives several testcases another's name: multiplexing,
  # blackhole, amplificationlimit, transferloss, transfercorruption and the
  # goodput and crosstraffic measurements are a transfer, keyupdate is one
  # to the server, longrtt is a handshake, and handshakeloss and
  # handshakecorruption are multiconnect, a connection for each request.
  # ecn goes as a handshake does, its packets marked ECT(0) as any are.
  module Runner
    CLIENT_TESTCASES = %w[
      handshake transfer retry chacha20 keyupdate versionnegotiation resumption zerortt http3 multiconnect ecn
    ].freeze
    SERVER_TESTCASES = %w[
      handshake transfer retry chacha20 versionnegotiation resumption zerortt http3 multiconnect ecn connectionmigration
    ].freeze
    # What quic-interop-runner takes for a testcase not implemented.
    NOT_IMPLEMENTED = 127

    def self.run(env: ENV, stdout: $stdout, stderr: $stderr)
      role = env["ROLE"] || "client"
      # quic-interop-runner sets TESTCASE inside the container (renamed
      # from the host-side TESTCASE_CLIENT / TESTCASE_SERVER). Local
      # smoke runs use the per-role names. Accept both.
      testcase = role == "server" ? env["TESTCASE_SERVER"] : env["TESTCASE_CLIENT"]
      testcase ||= env["TESTCASE"] || "handshake"
      testcases = role == "server" ? SERVER_TESTCASES : CLIENT_TESTCASES
      unless testcases.include?(testcase)
        stderr.puts("raiha-interop: unsupported testcase=#{testcase} role=#{role}")
        return NOT_IMPLEMENTED
      end
      runner = if testcase == "http3"
        role == "server" ? HTTP3Server : HTTP3Client
      else
        role == "server" ? Server : Client
      end
      runner.new(env:, testcase:, logger: stderr).run
    end
  end
end
