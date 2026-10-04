require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"
require "raiha/next/support/tls_oracle"

# A normal flight, mutated by code rather than listed by hand: each message
# left out, swapped with the next, sent twice, emptied, cut to one byte,
# announced larger than its limit, sent under another epoch, joined with
# the next across a key change, or split across one. Each mutation must
# close with the alert the rules below expect, never raise, and a
# handshake that still completes must satisfy the oracle. Closing some
# other way would mean an unchecked path was taken.
class RaihaNextTLSMutationTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW
  FINISHED = TLS::Handshake::Finished::MSG_TYPE

  Mutation = Data.define(:name, :inputs, :expected)

  # [epoch, bytes] for each message of `flight`, the epoch it is read in
  # once the message before it is handled, and the epoch after the last.
  def mutations(flight, final_epoch, limits)
    epochs = flight.map(&:first)
    after = ->(i) { epochs[i + 1] || final_epoch }
    type = ->(i) { flight[i].last.getbyte(0) }
    wrong_or_unexpected = ->(arriving, reading) { arriving == reading ? %i[unexpected_message unexpected_message] : %i[unexpected_message wrong_epoch] }
    malformed = ->(i) { type.(i) == FINISHED ? %i[decrypt_error bad_finished] : %i[decode_error malformed_message] }
    header = ->(t, length) { [t].pack("C") + [length].pack("N").byteslice(1, 3) }
    list = []
    flight.each_index do |i|
      rest = flight.dup.tap { |f| f.delete_at(i) }
      expected = i == flight.size - 1 ? :incomplete : wrong_or_unexpected.(epochs[i + 1], epochs[i])
      list << Mutation.new("omit #{i}", rest, expected)
      if i < flight.size - 1
        swapped = flight.dup.tap { |f| f[i], f[i + 1] = f[i + 1], f[i] }
        list << Mutation.new("swap #{i}", swapped, wrong_or_unexpected.(epochs[i + 1], epochs[i]))
        if epochs[i] != epochs[i + 1]
          joined = flight[0...i] + [[epochs[i], flight[i].last + flight[i + 1].last]]
          list << Mutation.new("join #{i} across the key change", joined, %i[unexpected_message handshake_data_spans_key_change])
          halves = [[epochs[i], flight[i].last.byteslice(0, 4)], [epochs[i + 1], flight[i].last.byteslice(4..)]]
          list << Mutation.new("split #{i} across the key change", flight[0...i] + halves, %i[unexpected_message wrong_epoch])
        end
      end
      list << Mutation.new("duplicate #{i}", flight[0..i] + [flight[i]], wrong_or_unexpected.(epochs[i], after.(i)))
      list << Mutation.new("empty #{i}", flight[0...i] + [[epochs[i], header.(type.(i), 0)]], malformed.(i))
      list << Mutation.new("one byte #{i}", flight[0...i] + [[epochs[i], header.(type.(i), 1) + "\x00".b]], malformed.(i))
      list << Mutation.new("too long #{i}", flight[0...i] + [[epochs[i], header.(type.(i), limits.(type.(i)) + 1)]],
        %i[decode_error message_too_large])
      other = epochs[i] == :application ? :handshake : :application
      list << Mutation.new("under #{other} #{i}", flight[0...i] + [[other, flight[i].last]], %i[unexpected_message wrong_epoch])
    end
    list
  end

  def limits(config) = ->(t) { [11, 13, 25].include?(t) ? config.max_certificate_message_size : config.max_handshake_message_size }

  def failure(machine) = machine.each_event.grep(TLS::Event::Failed).first&.then { |f| [f.alert, f.reason] }

  def run_mutation(receiver, mutation)
    mutation.inputs.each do |epoch, bytes|
      receiver.receive(bytes, epoch:, now: NOW)
      break if receiver.failed?
    end
    if mutation.expected == :incomplete
      refute receiver.failed?, mutation.name
      refute receiver.complete?, mutation.name
    else
      assert_equal mutation.expected, failure(receiver), mutation.name
    end
  end

  # The client receives the server's flight, mutated. The mutations of one
  # flight are the same for every handshake, so each runs on a fresh one,
  # made from that handshake's own messages.
  def test_server_flight_mutations
    config = Pair.client_config
    count = mutations(server_flight(config).last, :application, limits(config)).size
    assert_operator count, :>, 30
    count.times do |k|
      client, flight = server_flight(config)
      run_mutation(client, mutations(flight, :application, limits(config)).fetch(k))
    end
  end

  # The server receives the client's second flight, mutated, with and
  # without client authentication.
  def test_client_flight_mutations
    [:none, :required].each do |client_auth|
      config = Pair.server_config(client_auth:)
      count = mutations(client_flight(config).last, :application, limits(config)).size
      count.times do |k|
        server, flight = client_flight(config)
        mutation = mutations(flight, :application, limits(config)).fetch(k)
        run_mutation(server, mutation.with(name: "#{client_auth} #{mutation.name}"))
      end
    end
  end

  # A client waiting for the server's flight, and that flight.
  def server_flight(config)
    client = Pair.client(config:)
    server = Pair.server(client.outputs.first.bytes)
    [client, server.outputs.grep(TLS::Output::Message).map { |m| [m.epoch, m.bytes] }]
  end

  # A server waiting for the client's second flight, and that flight.
  def client_flight(server_config)
    client = Pair.client(identities: [Pair.client_identity])
    server = Pair.server(client.outputs.first.bytes, config: server_config)
    Pair.deliver(server.outputs, client)
    [server, client.outputs.grep(TLS::Output::Message).map { |m| [m.epoch, m.bytes] }]
  end

  # The unmutated handshakes complete, and the oracle holds for each.
  def test_oracle_holds_for_normal_handshakes
    [
      [{}, {}, :none],
      [{}, { config: Pair.server_config(groups: %i[secp256r1]) }, :none],
      [{ identities: [Pair.client_identity] }, { config: Pair.server_config(client_auth: :required) }, :required],
      [{}, { config: Pair.server_config(client_auth: :optional) }, :optional]
    ].each do |client_options, server_options, client_auth|
      oracle = NextTLSOracle.new
      client = Pair.client(**client_options, tracer: oracle.client)
      pair = Pair.run(client, { **server_options, tracer: oracle.server })
      assert pair.client.complete?
      assert pair.server.complete?
      assert_empty oracle.violations(client: pair.client, server: pair.server, client_auth:)
    end
  end

  # The oracle itself: a completed handshake without the traces of its
  # checks is reported.
  def test_oracle_reports_missing_checks
    oracle = NextTLSOracle.new
    pair = Pair.run(Pair.client, {})
    found = oracle.violations(client: pair.client, server: pair.server)
    assert_includes found, "the client completed without verifying the server's certificate and signature"
    assert_includes found, "the client completed without verifying the server's Finished"
    assert_includes found, "the server completed without verifying the client's Finished"
    assert_includes found, "the two sides completed with different transcripts"
  end
end
