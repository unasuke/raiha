require "raiha/tls"
require "socket"
require "timeout"

# A TCP::Connection of the next release of raiha over a TCP socket, driven
# by hand so that a test can write 0-RTT before the handshake completes and
# keep every event, which TCP::Socket does not let it.
class TCPDrive
  TLS = Raiha::TLS

  attr_reader :connection, :events

  def initialize(io, connection)
    @io = io
    @connection = connection
    @events = []
  end

  # Moves bytes both ways until the block is true, the peer closes, or
  # `timeout` seconds pass.
  def until(timeout: 5)
    Timeout.timeout(timeout) do
      loop do
        @connection.each_output { |bytes| @io.write(bytes) }
        take_events
        break if yield || @connection.failed?
        next unless IO.select([@io], nil, nil, 0.1)
        @connection.receive(@io.readpartial(65_536), now: Time.now)
      end
    end
    take_events
    self
  rescue EOFError, Errno::ECONNRESET
    take_events
    self
  end

  # All the peer's 1-RTT data until it closes, or `timeout` seconds pass.
  def read_all(timeout: 5)
    data = +""
    self.until(timeout:) do
      chunk = @connection.read(65_536)
      data << chunk if chunk
      chunk.nil?
    end
    data
  end

  def sessions = @events.grep(TLS::Event::NewSessionTicket).map(&:session)

  def completion = @events.grep(TLS::Event::HandshakeComplete).first

  def close
    @connection.close_notify unless @connection.failed?
    @connection.each_output { |bytes| @io.write(bytes) }
  rescue IOError, SystemCallError
    nil
  ensure
    @io.close unless @io.closed?
  end

  private def take_events
    while (event = @connection.next_event)
      @events << event
    end
  end
end
