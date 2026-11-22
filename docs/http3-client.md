# HTTP/3 client

A client is a `Raiha::QUIC::Connection.client` with a `Raiha::HTTP3::Connection.client` over it, joined by `Raiha::HTTP3Binding`, and a loop that you write around a UDP socket. None of them does I/O. The loop below blocks its thread on `IO.select` and needs no Fiber scheduler; under one, `Raiha::Runtime::Client.connect` and `Raiha::Runtime::HTTP3::Client` do the same in a few lines (see [fiber-scheduler.md](fiber-scheduler.md)).

The QUIC side of the loop is described in [quic.md](quic.md), the TLS and QUIC settings in [configuration.md](configuration.md), and the server these examples talk to in [http3-server.md](http3-server.md).

## A complete client

This client GETs `/hello` from the server at 127.0.0.1:4433, which presents a self-signed certificate for `localhost` from `cert.pem`, and prints the status and the body.

```ruby
require "raiha"
require "socket"

def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

tls_config = Raiha::TLS::Config.client(
  trust_anchors: [OpenSSL::X509::Certificate.new(File.read("cert.pem")).to_der],
  profile: Raiha::TLS::Profile::QUIC,
  alpn: ["h3"],
  registry: Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
)

socket = UDPSocket.new
socket.bind("127.0.0.1", 0)
quic = Raiha::QUIC::Connection.client(config: Raiha::QUIC::Config.new(ecn_address_families: [], enable_pmtud: false), tls_config:, keyring: Raiha::TLS::Keyring.client(config: tls_config),
  server_name: "localhost", remote: ["127.0.0.1", 4433], time: Time.now, now:)
http3 = Raiha::HTTP3::Connection.client
binding = Raiha::HTTP3Binding.new(quic, http3)

status = nil
body = +""
done = false

until done || quic.closed?
  quic.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
  deadline = quic.next_timeout
  if IO.select([socket], nil, nil, deadline && [deadline - now, 0].max)
    data, address = socket.recvfrom(65535)
    quic.receive(data, from: [address[3], address[1]], now:)
  end
  deadline = quic.next_timeout
  quic.handle_timeout(now:) if deadline && now >= deadline

  quic.each_event do |event|
    binding.receive(event, now:)
    next unless event.is_a?(Raiha::QUIC::Event::Connected)
    request = [[":method", "GET"], [":scheme", "https"], [":authority", "localhost"], [":path", "/hello"]]
    http3.send_request(quic.open_stream, request, fin: true)
  end
  binding.flush(now:)
  http3.each_event do |event|
    case event
    when Raiha::HTTP3::Event::Headers
      status = event.headers.to_h[":status"]
      done = event.fin
    when Raiha::HTTP3::Event::Data
      body << event.data
      done = event.fin
    when Raiha::HTTP3::Event::Trailers, Raiha::HTTP3::Event::Reset
      done = true
    end
  end
  binding.flush(now:)
end

quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:)
quic.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
puts status, body
```

`trust_anchors` is what the server's certificate is verified against, and `server_name` the name it is checked for and sent in SNI. To trust the system's CAs instead, see [configuration.md](configuration.md). `ecn_address_families: []` and `enable_pmtud: false` are for the plain `UDPSocket`, which neither marks ECN nor keeps IP from fragmenting path MTU probes; see [quic.md](quic.md#a-plain-socket).

## The loop

Each pass sends what is due, waits for a datagram or `quic.next_timeout`, hands any datagram to `quic.receive`, runs the timers with `handle_timeout` once `next_timeout` has come (whether or not a datagram came), and then takes what that brought: the QUIC events to `binding.receive`, `binding.flush`, the HTTP/3 events, and `binding.flush` again so that what you wrote goes to QUIC.

Keep that order, and check whether you are done right after taking the events, before the next wait. A loop that waits first and checks after can sleep through the end of the response: once the server has sent the last of it, no datagram may come until the idle timeout.

As at a server, a flush can bring HTTP/3 events of its own (`Raiha::HTTP3::Event::Writable`), so a client that sends large bodies goes round `flush` and `each_event` until a pass brings no event. The class at the end of this page does.

## Requests

A request goes on a bidirectional stream that QUIC opens: `quic.open_stream` returns its ID (0, 4, 8, ...), or `nil` while the server allows no more streams, in which case try again on a later pass; there is no event for it. Before the handshake has completed (`Raiha::QUIC::Event::Connected`) and outside 0-RTT, QUIC knows no limit yet and opens nothing.

`http3.send_request(stream_id, headers, fin: false)` sends the header section. `headers` is an Array of `[name, value]` Strings, the pseudo-header fields first: `:method`, `:scheme` (`https`), `:authority` and `:path`. Names must be lowercase. A malformed request raises `ArgumentError`; one after the server's GOAWAY raises `Raiha::HTTP3::Error::Usage`.

With `fin: true` the request has no body. Otherwise send it with `http3.send_data(stream_id, data, fin: true)`, which returns how many bytes it took. It holds at most 64 KiB for the stream (`max_send_buffer:` of `Connection.client`); with less taken than given, `Raiha::HTTP3::Event::Writable` tells when to give the rest, and `fin` applies only once all of it is taken. Trailers end the request: `send_headers` after the body.

```ruby
http3.send_request(stream_id, [[":method", "POST"], [":scheme", "https"], [":authority", "localhost"], [":path", "/upload"]])
http3.send_data(stream_id, "abc")
http3.send_headers(stream_id, [["x-sum", "3"]])
binding.flush(now:)
```

## Responses

The response comes as events of its stream:

| Event | What it means |
| --- | --- |
| `Raiha::HTTP3::Event::Headers` | A header section, `[":status", "200"]` first. A 1xx status is an interim response; the final one follows. `fin` when the response has no body. |
| `Raiha::HTTP3::Event::Data` | Some of the body, as it came. `fin` when it ends here, which may come with empty `data`. |
| `Raiha::HTTP3::Event::Trailers` | The trailer section, which ends the response. |
| `Raiha::HTTP3::Event::Reset` | The server reset the response, with the HTTP/3 `error_code` (for example `H3_REQUEST_REJECTED` after its GOAWAY). |
| `Raiha::HTTP3::Event::Stopped` | The server does not want the rest of the request's body. With `H3_NO_ERROR` it answers all the same. |
| `Raiha::HTTP3::Event::GoAway` | The server goes away: requests on streams from `stream_id` on were not processed, and no new request can be sent. |
| `Raiha::HTTP3::Event::Blocked` | A header section waits for the QPACK encoder stream, which can happen only when the client's `qpack_max_table_capacity` is above 0. Its `Headers` or `Trailers` follow; there is nothing to do. |
| `Raiha::HTTP3::Event::Datagram`, `Raiha::HTTP3::Event::Capsule` | An HTTP Datagram, or another capsule, for an Extended CONNECT request (RFC 9297). |

A malformed response never reaches you: HTTP/3 resets its stream with `H3_MESSAGE_ERROR` and gives `Reset`.

`http3.cancel(stream_id)` drops a request and its response both ways with `H3_REQUEST_CANCELLED`; call `binding.flush` after it. Events already queued for the stream may still come.

### Priority

A `priority` header field in the request (`[["priority", "u=5, i"]]`, RFC 9218) asks for the urgency and incrementality of the response. `http3.update_priority(stream_id, urgency: 1)` changes it while the request is open, sending a PRIORITY_UPDATE frame; it raises `Raiha::HTTP3::Error::Usage` once the request is over, and before the handshake has completed, while HTTP/3 has no control stream to send the frame on.

## Closing

`quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:)` closes with `H3_NO_ERROR`, HTTP/3's code for a clean close, then `each_transmit` sends the CONNECTION_CLOSE. Whichever end closes, and for whatever reason (an HTTP/3 error included, which the binding closes the connection for), `Raiha::QUIC::Event::Closed` comes with the `error` and whether it was `by_peer`, and `quic.closed?` turns true once the closing period is over.

## Several requests, resumption and 0-RTT

The class below keeps the responses of many requests on one connection by stream ID, and the session tickets and tokens the server gives for later connections:

- `Raiha::QUIC::Event::SessionTicket` gives a ticket as a `Raiha::QUIC::Session`. For HTTP/3 it goes with the server's SETTINGS, as `Raiha::HTTP3::Session.new(quic:, settings: http3.peer_settings)`, since requests in 0-RTT keep to the SETTINGS the ticket remembers. A server without ticket keys sends none.
- `Raiha::QUIC::Event::NewToken` gives a token, which spares a later connection the server's address validation.
- `Raiha::HTTP3::Session#to_h` and `Raiha::HTTP3::Session.from_h` turn a ticket into plain values and back, to keep it where you like. Use each ticket and token for one connection only, since using one again links the connections for anyone watching.

A later connection gives them to `Raiha::QUIC::Connection.client(session: ticket.quic, token:, early_data: true)` and to `Raiha::HTTP3::Connection.client(remembered: ticket.settings)` when `quic.zero_rtt_state` is `:pending`. It may then open streams and send requests at once, in 0-RTT, which an attacker can replay: send only requests that are safe to repeat.

If the server rejects the 0-RTT, `Raiha::QUIC::Event::ZeroRttRejected` comes, the streams opened in it are gone, and HTTP/3 starts over. Acknowledge it with `quic.acknowledge_zero_rtt_rejection`, give the binding a new HTTP/3 connection with `binding.restart`, and decide which requests to send again. `quic.zero_rtt_state` ends as `:accepted` or `:rejected`.

```ruby
# One HTTP/3 connection on its own UDP socket, and the responses to its
# requests by stream ID.
class Client
  attr_reader :quic, :http3, :responses, :tickets, :tokens, :rejected

  def initialize(host, port, server_name:, tls_config:, session: nil, token: nil, early_data: false)
    @socket = UDPSocket.new
    @socket.bind("127.0.0.1", 0)
    @quic = Raiha::QUIC::Connection.client(config: Raiha::QUIC::Config.new(ecn_address_families: [], enable_pmtud: false), tls_config:, keyring: Raiha::TLS::Keyring.client(config: tls_config),
      server_name:, remote: [host, port], time: Time.now, now:, session: session&.quic, token:, early_data:)
    # In 0-RTT, HTTP/3 keeps to the server's SETTINGS the ticket remembers.
    remembered = session.settings if @quic.zero_rtt_state == :pending
    @http3 = Raiha::HTTP3::Connection.client(remembered:)
    @binding = Raiha::HTTP3Binding.new(@quic, @http3)
    @authority = server_name
    @connected = false
    @responses = {}
    @unsent = {}
    @writable = []
    @tickets = []
    @tokens = []
    @rejected = []
  end

  # Whether requests can go: the handshake has completed, or 0-RTT goes.
  def ready? = @connected || @quic.zero_rtt_state == :pending

  # Sends a request, with `body` when given, on a new stream: its ID, or
  # nil when the server allows no more streams yet.
  def request(method, path, headers: [], body: nil)
    stream_id = @quic.open_stream or return nil
    pseudo = [[":method", method], [":scheme", "https"], [":authority", @authority], [":path", path]]
    @http3.send_request(stream_id, pseudo + headers, fin: body.nil?)
    @responses[stream_id] = { status: nil, headers: [], body: +"", trailers: [], done: false, request: [method, path] }
    write(stream_id, body) if body
    @binding.flush(now:)
    stream_id
  end

  def cancel(stream_id)
    @http3.cancel(stream_id)
    @responses.delete(stream_id)
    @binding.flush(now:)
  end

  def done?(stream_id) = @responses.fetch(stream_id)[:done]

  # The tickets to resume with, each with the server's SETTINGS.
  def http3_tickets
    settings = @http3.peer_settings or return []
    @tickets.map { |quic| Raiha::HTTP3::Session.new(quic:, settings:) }
  end

  # Runs passes until the block is true or the connection has closed.
  def run_until
    turn until yield || @quic.closed?
  end

  def close
    @quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:)
    @quic.each_transmit(now:) { |transmit| @socket.send(transmit.payload, 0, *transmit.destination) }
    @socket.close
  end

  # One pass: sends what is due, waits for a datagram or the next timer,
  # and takes what came.
  private def turn
    @quic.each_transmit(now:) { |transmit| @socket.send(transmit.payload, 0, *transmit.destination) }
    deadline = @quic.next_timeout
    if IO.select([@socket], nil, nil, deadline && [deadline - now, 0].max)
      data, address = @socket.recvfrom(65535)
      @quic.receive(data, from: [address[3], address[1]], now:)
    end
    deadline = @quic.next_timeout
    @quic.handle_timeout(now:) if deadline && now >= deadline
    @quic.each_event do |event|
      @binding.receive(event, now:)
      case event
      when Raiha::QUIC::Event::Connected then @connected = true
      when Raiha::QUIC::Event::SessionTicket then @tickets << event.session
      when Raiha::QUIC::Event::NewToken then @tokens << event.token
      when Raiha::QUIC::Event::ZeroRttRejected then restart
      end
    end
    loop do
      @binding.flush(now:)
      taken = 0
      @http3.each_event { |event| take(event); taken += 1 }
      @writable.each { |stream_id| (data = @unsent.delete(stream_id)) && write(stream_id, data) }
      @writable.clear
      break if taken.zero?
    end
  end

  private def take(event)
    case event
    when Raiha::HTTP3::Event::Writable then @writable << event.stream_id
    when Raiha::HTTP3::Event::Stopped then @unsent.delete(event.stream_id)
    when Raiha::HTTP3::Event::Headers
      response = @responses[event.stream_id] or return
      status = event.headers.to_h[":status"]
      return if status.start_with?("1") # an interim response
      response[:status] = Integer(status)
      response[:headers] = event.headers.reject { |name, _| name.start_with?(":") }
      response[:done] = event.fin
    when Raiha::HTTP3::Event::Data
      response = @responses[event.stream_id] or return
      response[:body] << event.data
      response[:done] = event.fin
    when Raiha::HTTP3::Event::Trailers
      response = @responses[event.stream_id] or return
      response[:trailers] = event.headers
      response[:done] = true
    when Raiha::HTTP3::Event::Reset
      @unsent.delete(event.stream_id)
      response = @responses[event.stream_id] or return
      response[:reset] = event.error_code
      response[:done] = true
    end
  end

  # Writes `data` and ends the request; what the stream does not take now
  # waits for Raiha::HTTP3::Event::Writable.
  private def write(stream_id, data)
    taken = @http3.send_data(stream_id, data, fin: true)
    @unsent[stream_id] = data.byteslice(taken..) if taken < data.bytesize
  end

  # The server rejected 0-RTT: the requests in it are gone, and HTTP/3
  # starts over. Which to send again is the application's to decide.
  private def restart
    @quic.acknowledge_zero_rtt_rejection
    @http3 = Raiha::HTTP3::Connection.client
    @binding.restart(@http3)
    @rejected = @responses.values.map { |response| response[:request] }
    @responses.clear
    @unsent.clear
  end
end
```

Used with `tls_config` as in the complete client, against a server that answers `/big` with a large body, as the `Handler` in [http3-server.md](http3-server.md#requests) does, and issues tickets and takes 0-RTT as in [its 0-RTT section](http3-server.md#settings-and-0-rtt). A server without ticket keys sends no ticket, and the wait for one below lasts until the idle timeout closes the connection.

```ruby
client = Client.new("127.0.0.1", 4433, server_name: "localhost", tls_config:)
client.run_until { client.ready? }
ids = [
  client.request("GET", "/a"),
  client.request("POST", "/upload", body: "y" * 300_000),
  client.request("GET", "/big")
]
client.run_until { ids.all? { |stream_id| client.done?(stream_id) } }
client.run_until { !client.http3_tickets.empty? && !client.tokens.empty? }
ticket = client.http3_tickets.last
token = client.tokens.last
client.close

again = Client.new("127.0.0.1", 4433, server_name: "localhost", tls_config:, session: ticket, token:, early_data: true)
# At once when 0-RTT goes; otherwise once the handshake completes.
again.run_until { again.ready? }
early = again.request("GET", "/early")
again.run_until { again.responses[early]&.fetch(:done) || !again.rejected.empty? }
p again.quic.zero_rtt_state # => :accepted, or :rejected with the request in again.rejected
again.close
```

The first connection's three requests go at once and their responses interleave. The 0-RTT request of the second goes before its handshake completes; whether the server takes it depends on its ticket keys and replay record (see [http3-server.md](http3-server.md#settings-and-0-rtt)).
