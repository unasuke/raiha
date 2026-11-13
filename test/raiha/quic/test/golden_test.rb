require "test_helper"
require "support/quic_golden"
require "digest"
require "stringio"

# Handshakes whose datagrams, every input fixed, are the same bytes as
# last time: their times, directions, sizes and SHA-256 are kept under
# golden/. A change to what goes on the wire shows here first; when it is
# meant, run with RAIHA_GOLDEN=update to write the files again.
class RaihaQUICTestGoldenTest < Minitest::Test
  include QUICGolden

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

  # With `qlog`, the ends write qlog, which changes nothing they send.
  def handshake(name, model: [], qlog: false)
    recorder = Recorder.new
    tracers = qlog ? %i[client server].to_h { [_1, QUIC::Qlog::Tracer.new(StringIO.new, vantage_point: _1)] } : {}
    net, client, server = network(seed: 7, recorder:, model:, tracers:)
    assert net.run_until { client.handshake_confirmed? && server.connections.any?(&:handshake_confirmed?) }
    assert_golden(name, lines(recorder))
  end

  LOSS = [QUIC::Test::RandomLoss.new(rate: 0.3), QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)].freeze

  def test_a_handshake
    handshake("handshake")
  end

  def test_a_handshake_over_loss
    handshake("handshake_over_loss", model: LOSS)
  end

  def test_qlog_changes_nothing_sent
    handshake("handshake", qlog: true)
    handshake("handshake_over_loss", model: LOSS, qlog: true)
  end
end
