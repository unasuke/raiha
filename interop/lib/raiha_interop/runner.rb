# frozen_string_literal: true

require_relative "client_runner"
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
      testcase = role == "server" ? env["TESTCASE_SERVER"] : env["TESTCASE_CLIENT"]
      testcase ||= env["TESTCASE"] || "handshake"

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
