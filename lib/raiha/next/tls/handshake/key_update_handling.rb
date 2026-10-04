# frozen_string_literal: true

require_relative "key_update"

module Raiha::Next::TLS
  module Handshake
    # A KeyUpdate from the peer over TCP, the same for both roles (RFC 9846
    # "Key and Initialization Vector Update"): read with the next
    # generation, and when the peer asks, answer with a KeyUpdate of our own,
    # sent under the old key and followed by our next write Secret. QUIC
    # updates keys on its own and never gets here.
    #
    # RFC 9846 limits how many times a sender updates, never the receiver: a
    # request past our limit is ignored, while the peer's updates are always
    # followed.
    module KeyUpdateHandling
      MAX_KEY_UPDATES = (1 << 48) - 1

      # A KeyUpdate changes keys, so it has to end its record (RFC 9846
      # "Record Protocol"); bytes after it fail before anything changes.
      private def receive_key_update(message, peer:, own:)
        return fail!(:unexpected_message, :handshake_data_spans_key_change) if @conductor.pending_input?
        schedule = key_schedule
        @conductor.change_epochs!(cipher_suite: suite,
          secrets: [[:application, :read, schedule.update_application_traffic_secret!(peer)]])
        return unless message.request_update == KeyUpdate::UPDATE_REQUESTED
        return if @key_updates >= MAX_KEY_UPDATES
        @conductor.emit_message!(:application, KeyUpdate.new(request_update: KeyUpdate::UPDATE_NOT_REQUESTED))
        @conductor.close_flight!
        @key_updates += 1
        @conductor.change_epochs!(cipher_suite: suite,
          secrets: [[:application, :write, schedule.update_application_traffic_secret!(own)]])
      end
    end
  end
end
