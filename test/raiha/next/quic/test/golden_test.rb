require "raiha/next/test_helper"
require "raiha/next/support/quic_golden"
require "digest"

# Handshakes whose datagrams, every input fixed, are the same bytes as
# last time: their times, directions, sizes and SHA-256 are kept under
# golden/. A change to what goes on the wire shows here first; when it is
# meant, run with RAIHA_GOLDEN=update to write the files again.
class RaihaNextQUICTestGoldenTest < Minitest::Test
  include NextQUICGolden

  DIRECTORY = File.join(__dir__, "golden")

  # The lines of the datagrams `recorder` kept.
  def lines(recorder)
    recorder.log.map do |time, source, payload|
      direction = source == CLIENT ? "client" : "server"
      format("%.6f %s %d %s", time, direction, payload.bytesize, Digest::SHA256.hexdigest(payload))
    end
  end

  def assert_golden(name, lines)
    path = File.join(DIRECTORY, "#{name}.txt")
    if ENV["RAIHA_GOLDEN"] == "update"
      File.write(path, lines.join("\n") + "\n")
      skip "wrote #{path}"
    end
    assert_equal File.read(path).lines(chomp: true), lines
  end

  def handshake(name, model: [])
    recorder = Recorder.new
    net, client, server = network(seed: 7, recorder:, model:)
    assert net.run_until { client.handshake_confirmed? && server.connections.any?(&:handshake_confirmed?) }
    assert_golden(name, lines(recorder))
  end

  def test_a_handshake
    handshake("handshake")
  end

  def test_a_handshake_over_loss
    model = [QUIC::Test::RandomLoss.new(rate: 0.3), QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)]
    handshake("handshake_over_loss", model:)
  end
end
