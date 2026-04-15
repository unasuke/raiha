require "test_helper"
require "raiha/qlog"
require "stringio"
require "tempfile"

class RaihaQlogWriterTest < Minitest::Test
  def test_writer_json_output
    output = StringIO.new
    writer = Raiha::Qlog::Writer.new(output: output, title: "Test")
    writer.start_trace(vantage_point: :client, connection_id: "abc123")

    event = Raiha::Qlog::ConnectionEvents::ConnectionStarted.new(
      src_cid: "abc123", dest_cid: "def456"
    )
    writer.log(event)
    writer.flush

    json = JSON.parse(output.string)
    assert_equal "0.4", json["qlog_version"]
    assert_equal "JSON", json["qlog_format"]
    assert_equal "Test", json["title"]
    assert_equal 1, json["traces"].size

    trace = json["traces"][0]
    assert_equal "Connection abc123", trace["title"]
    assert_equal "client", trace["vantage_point"]["type"]
    assert_equal "QUIC", trace["common_fields"]["protocol_type"]
    assert_equal "relative", trace["common_fields"]["time_format"]

    assert_equal 1, trace["events"].size
    event_data = trace["events"][0]
    assert_equal "connectivity:connection_started", event_data["name"]
    assert_kind_of Numeric, event_data["time"]
  end

  def test_writer_server_vantage_point
    output = StringIO.new
    writer = Raiha::Qlog::Writer.new(output: output)
    writer.start_trace(vantage_point: :server, connection_id: "xyz")
    writer.flush

    json = JSON.parse(output.string)
    assert_equal "server", json["traces"][0]["vantage_point"]["type"]
  end

  def test_writer_relative_time
    output = StringIO.new
    writer = Raiha::Qlog::Writer.new(output: output)
    writer.start_trace(vantage_point: :client, connection_id: "test")

    event = Raiha::Qlog::Event.new(category: :test, event_type: :test)
    writer.log(event)
    writer.flush

    json = JSON.parse(output.string)
    time = json["traces"][0]["events"][0]["time"]
    assert_operator time, :>=, 0
    assert_operator time, :<, 1000
  end

  def test_writer_to_file
    tempfile = Tempfile.new(["qlog", ".json"])
    Raiha::Qlog::Writer.to_file(tempfile.path, title: "File Test") do |writer|
      writer.start_trace(vantage_point: :client, connection_id: "file_test")
      writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :test))
    end

    json = JSON.parse(File.read(tempfile.path))
    assert_equal "File Test", json["title"]
    assert_equal 1, json["traces"].size
  ensure
    tempfile&.close!
  end

  def test_writer_no_trace_ignores_log
    output = StringIO.new
    writer = Raiha::Qlog::Writer.new(output: output)
    writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :test))
    writer.flush

    json = JSON.parse(output.string)
    assert_empty json["traces"]
  end

  def test_writer_multiple_events
    output = StringIO.new
    writer = Raiha::Qlog::Writer.new(output: output)
    writer.start_trace(vantage_point: :client, connection_id: "multi")

    3.times do |i|
      writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :"event_#{i}"))
    end
    writer.flush

    json = JSON.parse(output.string)
    events = json["traces"][0]["events"]
    assert_equal 3, events.size
    assert_equal "test:event_0", events[0]["name"]
    assert_equal "test:event_2", events[2]["name"]
  end

  def test_streaming_writer_ndjson_output
    output = StringIO.new
    writer = Raiha::Qlog::StreamingWriter.new(output: output)
    writer.start_trace(vantage_point: :client, connection_id: "stream_test")
    writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :first))
    writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :second))

    lines = output.string.lines
    assert_equal 4, lines.size

    header = JSON.parse(lines[0])
    assert_equal "0.4", header["qlog_version"]
    assert_equal "JSON-SEQ", header["qlog_format"]

    trace = JSON.parse(lines[1])
    assert_equal "Connection stream_test", trace["title"]
    assert_equal "client", trace["vantage_point"]["type"]

    event1 = JSON.parse(lines[2])
    assert_equal "test:first", event1["name"]

    event2 = JSON.parse(lines[3])
    assert_equal "test:second", event2["name"]
  end

  def test_streaming_writer_relative_time
    output = StringIO.new
    writer = Raiha::Qlog::StreamingWriter.new(output: output)
    writer.start_trace(vantage_point: :server, connection_id: "t")
    writer.log(Raiha::Qlog::Event.new(category: :test, event_type: :t))

    lines = output.string.lines
    event = JSON.parse(lines.last)
    assert_operator event["time"], :>=, 0
    assert_operator event["time"], :<, 1000
  end
end
