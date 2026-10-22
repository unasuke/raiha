# frozen_string_literal: true

require_relative "client_runner"
require_relative "next_runner"
require_relative "server_runner"
require_relative "testcases"

module RaihaInterop
  # Top-level entry point used by interop/bin/raiha-interop. Reads
  # quic-interop-runner environment variables to decide which
  # role / testcase to run, then delegates to ClientRunner or
  # ServerRunner. Returns an integer exit status.
  module Runner
    def self.run(env: ENV, stdout: $stdout, stderr: $stderr)
      role = env["ROLE"] || "client"
      # quic-interop-runner sets TESTCASE inside the container (renamed
      # from the host-side TESTCASE_CLIENT / TESTCASE_SERVER). Local
      # smoke runs use the per-role names. Accept both.
      testcase = role == "server" ? env["TESTCASE_SERVER"] : env["TESTCASE_CLIENT"]
      testcase ||= env["TESTCASE"] || "handshake"
      # The image built with RAIHA_IMPL=next runs the next release of raiha.
      return NextRunner.run(env:, role:, testcase:, logger: stderr) if env["RAIHA_IMPL"] == "next"

      unless Testcases.supported?(testcase)
        stderr.puts "raiha-interop: unsupported testcase=#{testcase} role=#{role}"
        return 127 # quic-interop-runner expects 127 for "not implemented"
      end

      case role
      when "server" then ServerRunner.new(env: env, testcase: testcase, logger: stderr).run
      when "client" then ClientRunner.new(env: env, testcase: testcase, logger: stderr).run
      else
        stderr.puts "raiha-interop: unknown ROLE=#{role.inspect}"
        2
      end
    end
  end
end
