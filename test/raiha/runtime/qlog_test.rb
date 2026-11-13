require "test_helper"
require "support/runtime_http3"
require "async"
require "json"
require "timeout"
require "tmpdir"

# The qlog of the runtime: a file for each connection of a client and a
# server, written after the turn that traced it and closed once the
# connection is over, and one budget for the traces of a worker.
class RaihaNextRuntimeQlogTest < Minitest::Test
  include NextRuntimeHTTP3

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

  # A connection of HTTP/3 has the events of HTTP/3 in its qlog, under the
  # schema the header names, at either end.
  def test_the_events_of_http3
    Dir.mktmpdir do |dir|
      Sync do
        tls = h3_server_config
        server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
          port: 0, qlog_dir: File.join(dir, "server"))
        running = Fiber.schedule { server.run { |request| request.respond(200, [], "traced") } }
        sleep 0.01 until server.local_address
        tls = h3_client_config
        body = Runtime::Client.connect("127.0.0.1", server.local_address.fetch(1), config: QUIC::Config.new, tls_config: tls,
          keyring: client_keyring(config: tls), server_name: "localhost", qlog_dir: File.join(dir, "client")) do |session|
          Runtime::HTTP3::Client.new(session).get("/").body
        end
        assert_equal "traced", body
      ensure
        server&.stop(timeout: 1)
        sleep 0.01 while running&.alive?
      end
      %w[server client].each do |vantage_point|
        header, *events = records(Dir[File.join(dir, vantage_point, "*.sqlog")].fetch(0))
        assert_includes header.dig("trace", "event_schemas"), Raiha::Next::HTTP3::Qlog::EVENT_SCHEMA
        assert_includes events.map { _1["name"] }, "http3:frame_parsed"
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
      _, writing = qlog.trace(:server, "new", tls_config: server_config)
      assert_equal old.last(3), old.select { File.exist?(_1) }
      writing.write("y" * 300)
      qlog.flush
      _, newer = qlog.trace(:server, "newer", tls_config: server_config)
      assert_equal [writing.path], (old + [writing.path]).select { File.exist?(_1) }
      writing.over!
      newer.write("z" * 100)
      qlog.flush
      qlog.trace(:server, "newest", tls_config: server_config)
      assert_equal [newer.path], [writing.path, newer.path].select { File.exist?(_1) }
      assert File.exist?(File.join(dir, "notes.txt"))
    end
  end

  # A file another Qlog of the same directory is writing is not taken away,
  # though the first counted it among the old ones.
  def test_a_file_another_writer_holds_stays
    Dir.mktmpdir do |dir|
      other = Runtime::Qlog.new(dir)
      _, live = other.trace(:server, "live", tls_config: server_config)
      live.write("x" * 100)
      other.flush
      qlog = Runtime::Qlog.new(dir, max_files: 1)
      qlog.trace(:server, "mine", tls_config: server_config)
      assert File.exist?(live.path)
      live.over!
      other.flush
    end
  end

  # A FIFO or a symbolic link in place of a file neither stops the Qlog nor
  # takes what it writes: a trace that cannot have a regular file of its
  # own is dropped, and an old file turned into something else stays.
  def test_what_is_not_a_regular_file
    Dir.mktmpdir do |dir|
      old = File.join(dir, "old_server.sqlog")
      File.binwrite(old, "x")
      target = File.join(dir, "elsewhere")
      File.binwrite(target, "kept")
      File.mkfifo(File.join(dir, "fifo_server.sqlog"))
      File.symlink(target, File.join(dir, "link_server.sqlog"))
      qlog = Runtime::Qlog.new(dir, max_files: 1)
      File.delete(old)
      File.mkfifo(old)
      Timeout.timeout(5) do
        traces = %w[fifo link].map { qlog.trace(:server, _1, tls_config: server_config).last }
        traces.each { _1.write("written") && _1.over! }
        qlog.flush
      end
      assert File.pipe?(old)
      assert_equal "kept", File.binread(target)
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
      assert_equal 0o600, File.stat(pending.path).mode & 0o777
    end
  end
end
