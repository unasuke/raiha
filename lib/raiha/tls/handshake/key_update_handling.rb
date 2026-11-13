# frozen_string_literal: true

require_relative "key_update"

module Raiha::TLS
  module Handshake
    # KeyUpdate over TCP, the same for both roles (RFC 9846 "Key and
    # Initialization Vector Update"). QUIC updates keys on its own and never
    # gets here.
    #
    # A peer's KeyUpdate moves our reading to the next generation. When it
    # asks for one back, we owe a single KeyUpdate however many requests
    # come, and send it only right before our next application data: RFC
    # 9846 lets a silent side answer many requests once, so what the peer
    # sends never makes us write. A run of more than
    # MAX_CONSECUTIVE_KEY_UPDATES without application data from the peer
    # ends the connection.
    #
    # RFC 9846 limits how many times a sender updates, never the receiver:
    # past MAX_KEY_UPDATES we stop sending, while the peer's updates are
    # always followed.
    module KeyUpdateHandling
      MAX_KEY_UPDATES = (1 << 48) - 1
      # BoringSSL's kMaxKeyUpdates, which rustls uses too.
      MAX_CONSECUTIVE_KEY_UPDATES = 32

      # How many KeyUpdates we have sent: the epoch RFC 9846 limits.
      attr_reader :key_updates

      # Owes the peer an answer before our next application data.
      def before_application_data
        send_key_update(KeyUpdate::UPDATE_NOT_REQUESTED) if @key_update_owed
        nil
      end

      # The peer's run of KeyUpdates ends.
      def application_data_received
        @consecutive_key_updates = 0
        nil
      end

      # A KeyUpdate of our own. A KeyUpdate we owe goes first and also
      # serves for one that does not ask for the peer's. While our request
      # waits for the peer's KeyUpdate, another one cannot ask again.
      def request_key_update(request_peer_update:)
        owed = @key_update_owed
        before_application_data
        return nil if owed && !request_peer_update
        send_key_update(request_peer_update ? KeyUpdate::UPDATE_REQUESTED : KeyUpdate::UPDATE_NOT_REQUESTED)
        nil
      end

      private def start_key_updates
        @key_updates = 0
        @consecutive_key_updates = 0
        @key_update_owed = false
        @awaiting_peer_update = false
      end

      # A KeyUpdate changes keys, so it has to end its record (RFC 9846
      # "Record Protocol"); that, and the run of KeyUpdates, are checked
      # before anything changes or is owed.
      private def receive_key_update(message)
        return fail!(:unexpected_message, :handshake_data_spans_key_change) if @conductor.pending_input?
        @consecutive_key_updates += 1
        return fail!(:unexpected_message, :too_many_key_updates) if @consecutive_key_updates > MAX_CONSECUTIVE_KEY_UPDATES
        @conductor.change_epochs!(cipher_suite: suite,
          secrets: [[:application, :read, key_schedule.update_application_traffic_secret!(peer_side)]])
        @awaiting_peer_update = false
        @key_update_owed = true if message.request_update == KeyUpdate::UPDATE_REQUESTED
        nil
      end

      # Sent under the old key, then the next write Secret.
      private def send_key_update(request)
        @key_update_owed = false
        return if @key_updates >= MAX_KEY_UPDATES
        request = KeyUpdate::UPDATE_NOT_REQUESTED if @awaiting_peer_update
        @conductor.emit_message!(:application, KeyUpdate.new(request_update: request))
        @conductor.close_flight!
        @key_updates += 1
        @awaiting_peer_update = true if request == KeyUpdate::UPDATE_REQUESTED
        @conductor.change_epochs!(cipher_suite: suite,
          secrets: [[:application, :write, key_schedule.update_application_traffic_secret!(own_side)]])
      end
    end
  end
end
