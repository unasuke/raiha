require "raiha/next/test_helper"
require "raiha/next/support/runtime_owner"
require "async"
require "json"
require "tmpdir"

# The qlog of the runtime: a file for each connection of a client and a
# server, written after the turn that traced it and closed once the
# connection is over, and one budget for the traces of a worker.
class RaihaNextRuntimeQlogTest < Minitest::Test
  include NextRuntimeOwner

  # The records of a JSON Text Sequence.
  def records(path) = File.binread(path).split("\x1e").reject(&:empty?).map { JSON.parse(_1) }

  def test_a_file_for_each_connection_at_each_end
    Dir.mktmpdir do |dir|
      Sync do
        tls = server_config
        server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
          port: 0, qlog_dir: File.join(dir, "server"))
        running = Fiber.schedule { server.run { |session| session.each_stream { |stream| (stream << stream.read).close_write } } }
        sleep 0.01 until server.local_address
        tls = client_config
        echoed = Runtime::Client.connect("127.0.0.1", server.local_address.fetch(1), config: QUIC::Config.new, tls_config: tls,
          keyring: client_keyring(config: tls), server_name: "localhost", qlog_dir: File.join(dir, "client")) do |session|
          stream = session.open_stream
          (stream << "traced").close_write
          stream.read
        end
        assert_equal "traced", echoed
        server.stop(timeout: 1)
        sleep 0.01 while running.alive?
        assert_empty server.instance_variable_get(:@qlog).instance_variable_get(:@pending)
      end
      server_files = Dir[File.join(dir, "server", "*_server.sqlog")]
      client_files = Dir[File.join(dir, "client", "*_client.sqlog")]
      assert_equal [1, 1], [server_files.size, client_files.size]
      assert_match(/\A\h{16,40}_server\.sqlog\z/, File.basename(server_files.first))
      [server_files.first, client_files.first].zip(%w[server client]).each do |path, vantage_point|
        header, *events = records(path)
        assert_equal vantage_point, header.dig("trace", "vantage_point", "type")
        assert_includes events.map { _1["name"] }, "quic:packet_received"
      end
    end
  end

  # One budget for the traces of a Ractor, whichever client or server
  # writes them.
  def test_one_budget_for_a_worker
    Dir.mktmpdir do |dir|
      assert_same Runtime::Qlog.budget, Runtime::Qlog.new(dir).budget
      assert_same Runtime::Qlog.new(dir).budget, Runtime::Qlog.new(File.join(dir, "other")).budget
      assert_equal 1024**3, Runtime::Qlog.budget.max_bytes
    end
  end

  # Before a trace begins, the oldest files no trace writes to go, those of
  # earlier runs first, until the new one fits in the count and the
  # directory in its bytes.
  def test_rotation
    Dir.mktmpdir do |dir|
      old = Array.new(5) do |i|
        File.join(dir, "old#{i}_server.sqlog").tap do |path|
          File.binwrite(path, "x" * 100)
          File.utime(Time.at(1_000 + i), Time.at(1_000 + i), path)
        end
      end
      File.binwrite(File.join(dir, "notes.txt"), "kept")
      qlog = Runtime::Qlog.new(dir, max_bytes: 350, max_files: 4)
      _, writing = qlog.trace(:server, "new")
      assert_equal old.last(3), old.select { File.exist?(_1) }
      writing.write("y" * 300)
      qlog.flush
      _, newer = qlog.trace(:server, "newer")
      assert_equal [writing.path], (old + [writing.path]).select { File.exist?(_1) }
      writing.over!
      newer.write("z" * 100)
      qlog.flush
      qlog.trace(:server, "newest")
      assert_equal [newer.path], [writing.path, newer.path].select { File.exist?(_1) }
      assert File.exist?(File.join(dir, "notes.txt"))
    end
  end

  # What a trace writes while its file is being written goes in the next
  # flush, and a file is closed once its connection is over.
  def test_pending_writes
    Dir.mktmpdir do |dir|
      pending = Runtime::Qlog::Pending.new(File.join(dir, "a.sqlog"))
      assert_equal 3, pending.write("a", "bc")
      refute pending.flush
      pending.write("d")
      pending.over!
      assert pending.flush
      assert_equal "abcd", File.binread(pending.path)
    end
  end
end
