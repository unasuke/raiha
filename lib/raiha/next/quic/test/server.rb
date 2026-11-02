# frozen_string_literal: true

module Raiha::Next::QUIC::Test
  # A server's Endpoint on a Network, run as an application that takes
  # every offer would run it: each offer is admitted and each ClientHello
  # accepted with one TLS Config and Keyring, and what the Endpoint answers
  # itself is sent. With `retry_unvalidated`, an offer whose address is not
  # validated gets a Retry instead. A Config that takes 0-RTT needs
  # `anti_replay`, given to each connection.
  class Server
    attr_reader :endpoint

    def initialize(endpoint, tls_config:, keyring:, retry_unvalidated: false, tracer: nil, anti_replay: nil)
      @endpoint = endpoint
      @tls_config = tls_config
      @keyring = keyring
      @retry_unvalidated = retry_unvalidated
      @tracer = tracer
      @anti_replay = anti_replay
      @transmits = [] #: Array[Raiha::Next::QUIC::Transmit]
    end

    def receive(payload, from:, to:, ecn:, now:) = dispatch(@endpoint.receive(payload, from:, to:, ecn:, now:), now)

    def each_transmit(now:, &)
      while (transmit = @transmits.shift)
        yield transmit
      end
      @endpoint.each_transmit(now:, &)
    end

    def next_timeout = @endpoint.next_timeout

    def handle_timeout(now:) = @endpoint.handle_timeout(now:)

    # The connections the Endpoint has taken.
    def connections
      all = [] #: Array[Raiha::Next::QUIC::Connection]
      @endpoint.each_connection { |connection| all << connection }
      all
    end

    private def dispatch(route, now)
      case route
      when Raiha::Next::QUIC::Route::Incoming
        return @endpoint.retry(route.handle, now:) if @retry_unvalidated && !route.address_validated
        dispatch(@endpoint.admit(route.handle, now:), now)
      when Raiha::Next::QUIC::Route::ClientHello
        @endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:, tracer: @tracer, anti_replay: @anti_replay)
      when Raiha::Next::QUIC::Route::Respond then @transmits << route.transmit
      end
    end
  end
end
