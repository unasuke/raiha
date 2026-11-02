require "raiha/next/test_helper"
require "raiha/next/support/runtime_http3"
require "async"

# Resumption and 0-RTT of the runtime's HTTP/3: a server's 0-RTT bound to
# its SETTINGS.
class RaihaNextRuntimeHTTP3ZeroRTTTest < Minitest::Test
  include NextRuntimeHTTP3

  SEED = "\x22".b * 32

  # One TLS Config for every server, so that a ticket of one resumes
  # another.
  def tls = @tls ||= NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY, ticket_key: SEED, max_early_data_size: 16_384)

  # A server of HTTP/3 on a free port answering each request with
  # `handler`, for the block, which is given its port; stopped after.
  def serving(handler = ->(request) { request.respond(200, [], "ok") }, settings: HTTP3::Settings.new,
    anti_replay: TLS::AntiReplay::Memory.new(now: Time.now, warmup: false))
    server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0, settings:, anti_replay:)
    running = Fiber.schedule { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1)
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  # A ticket the server on `port` gives, as a QUIC::Session.
  def quic_ticket(port)
    h3_connect(port) do |session|
      session.wait_for(deadline: Runtime::Driver.clock + 2) { session.tickets.first }
      session.tickets.last
    end
  end

  # The tickets of the client of HTTP/3 come with the server's SETTINGS.
  def test_tickets_with_the_servers_settings
    Sync do
      settings = HTTP3::Settings.new(max_field_section_size: 1000)
      tickets = serving(settings:) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_equal "ok", client.get("/").body
          session.wait_for(deadline: Runtime::Driver.clock + 2) { client.tickets.first }
          client.tickets
        end
      end
      refute_empty tickets
      assert_equal [settings], tickets.map(&:settings).uniq
      assert_equal [QUIC::Session], tickets.map { _1.quic.class }.uniq
    end
  end

  # A server's SETTINGS are part of what its 0-RTT is taken with: the
  # ticket of a server of other SETTINGS resumes, but its 0-RTT is
  # rejected (RFC 9114 "Initialization").
  def test_settings_bind_0rtt
    Sync do
      ticket = serving { |port| quic_ticket(port) }
      states = [HTTP3::Settings.new, HTTP3::Settings.new(max_field_section_size: 1000)].map do |settings|
        serving(settings:) do |port|
          h3_connect(port, session: ticket, early_data: true) do |session|
            session.wait_handshake
            [session.handshake&.resumed, session.connection.zero_rtt_state]
          end
        end
      end
      assert_equal [[true, :accepted], [true, :rejected]], states
    end
  end
end
