# frozen_string_literal: true

require_relative "next_runner"

module RaihaInterop
  # Top-level entry point used by interop/bin/raiha-interop. Reads
  # quic-interop-runner environment variables to decide which
  # role / testcase to run, then delegates to NextRunner. Returns an
  # integer exit status.
  module Runner
    def self.run(env: ENV, stdout: $stdout, stderr: $stderr)
      role = env["ROLE"] || "client"
      # quic-interop-runner sets TESTCASE inside the container (renamed
      # from the host-side TESTCASE_CLIENT / TESTCASE_SERVER). Local
      # smoke runs use the per-role names. Accept both.
      testcase = role == "server" ? env["TESTCASE_SERVER"] : env["TESTCASE_CLIENT"]
      testcase ||= env["TESTCASE"] || "handshake"
      NextRunner.run(env:, role:, testcase:, logger: stderr)
    end
  end
end
