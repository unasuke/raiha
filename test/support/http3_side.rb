require "raiha/http3_binding"

# One end's application over HTTP/3 of raiha: its
# QUIC connection joined to an HTTP/3 connection by HTTP3Binding, run in
# turns, with the events of each it was left with.
class HTTP3Side
  attr_reader :connection, :http3, :binding, :events, :quic_events

  def initialize(connection, http3)
    @connection = connection
    @http3 = http3
    @binding = Raiha::HTTP3Binding.new(connection, http3)
    @events = []
    @quic_events = []
  end

  # The QUIC connection's events to the binding, the rest kept; HTTP/3's
  # events kept and given to `on_event`; then the block; and what all of
  # it wrote out.
  def turn(now, on_event = nil)
    @connection.each_event { |event| @binding.receive(event, now:) or @quic_events << event }
    @binding.flush(now:)
    @http3.each_event do |event|
      @events << event
      on_event&.call(self, event)
    end
    yield if block_given?
    @binding.flush(now:)
  end

  def of(type) = @events.grep(type)

  # HTTP/3 starts over with `http3`, after a rejected 0-RTT.
  def restart(http3)
    @http3 = http3
    @binding.restart(http3)
  end
end
