# frozen_string_literal: true

require_relative "../error"
require_relative "../iana"
require_relative "../profile"
require_relative "../record"
require_relative "../handshake/acceptor"

module Raiha::Next::TLS
  module TCP
    # The start of a TCP server's handshake, before a Config is chosen: the
    # Handshake::Acceptor behind the record layer. It reads plaintext records
    # until a ClientHello is whole and offers it as `accepted`; the
    # application picks a Config and a Keyring by it and passes this to
    # TCP::Connection.server, or turns the client down with `reject`.
    #
    # Bytes that come after the ClientHello are kept as they came, up to
    # MAX_HELD_BYTES, for the Connection to read first. Bytes from the peer
    # never raise.
    class Acceptor
      MAX_HELD_BYTES = 64 * 1024

      def initialize
        @acceptor = Handshake::Acceptor.new
        @record = Record::Layer.new(profile: Profile::TCP)
        @outgoing = "".b
        @alert = nil #: Symbol?
        @reason = nil #: Symbol?
        @peer_alerted = false
        @handed_over = false
      end

      # Bytes read from the socket, in any pieces.
      def receive(bytes, now:)
        return nil if failed?
        @record << bytes
        return hold if @acceptor.accepted
        until failed? || @acceptor.accepted || (record = @record.read(epoch: :initial)).nil?
          case record
          when Record::Failure then fail!(record.alert, record.reason)
          else take(record, now)
          end
        end
        hold if @acceptor.accepted
        nil
      end

      # The bytes to write to the socket, if any: only ever an alert.
      def each_output
        return if @outgoing.empty?
        bytes = @outgoing
        @outgoing = "".b
        yield bytes
      end

      # The ClientHello once whole and valid; nil before, and after a failure.
      def accepted = failed? ? nil : @acceptor.accepted

      # Turns the ClientHello down with one of Handshake::Acceptor::REJECT_ALERTS.
      def reject(description)
        @acceptor.reject(description)
        send_alerts
      end

      def failed? = !@alert.nil? || @peer_alerted || @acceptor.failed?

      # The alert sent, if any: none answers the peer's own alert.
      def alert = @alert || @acceptor.alert

      def reason = @reason || @acceptor.reason

      # What a Connection takes over, once: the ClientHello and the record
      # layer holding the bytes that came after it.
      def hand_over
        accepted = self.accepted or raise UsageError, "the Acceptor has accepted no ClientHello"
        raise UsageError, "the Acceptor has been handed over already" if @handed_over
        @handed_over = true
        [accepted, @record]
      end

      # Only handshake records come before the ClientHello is whole, and none
      # of another type in between its pieces (RFC 9846 "Record Layer").
      private def take(record, now)
        case record.content_type
        when :handshake
          @acceptor.receive(record.payload, epoch: :initial, now:)
          send_alerts
        when :alert
          # The client gave up; there is nobody to answer.
          @peer_alerted = true
          @reason = :peer_alert
          @record.discard!
        else
          fail!(:unexpected_message, :unexpected_record)
        end
      end

      # The bytes after the ClientHello wait for the Connection, but not
      # without bound (the Acceptor may wait long for the application).
      private def hold
        fail!(:unexpected_message, :too_much_data_before_accept) if @record.pending_bytes > MAX_HELD_BYTES
        nil
      end

      private def send_alerts
        @acceptor.each_output do |output|
          @outgoing << @record.write(content_type: :alert, payload: [2, IANA.alert_code(output.description)].pack("C2"), epoch: :initial)
        end
        nil
      end

      private def fail!(alert, reason)
        @alert = alert
        @reason = reason
        @outgoing << @record.write(content_type: :alert, payload: [2, IANA.alert_code(alert)].pack("C2"), epoch: :initial)
        @record.discard!
        nil
      end
    end
  end
end
