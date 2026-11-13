require "test_helper"
require "raiha/tls"

class RaihaNextTLSEventTest < Minitest::Test
  SessionNotOffered = Raiha::Next::TLS::Event::SessionNotOffered

  # Expired tickets and chains that no longer verify can never be used
  # again; the other reasons depend on this connection.
  def test_session_not_offered_discard
    %i[ticket_expired certificate_expired untrusted_chain].each do |reason|
      assert SessionNotOffered.new(reason:).discard?, reason
    end
    %i[unverified_origin server_name_mismatch cipher_suite_unavailable].each do |reason|
      refute SessionNotOffered.new(reason:).discard?, reason
    end
  end
end
