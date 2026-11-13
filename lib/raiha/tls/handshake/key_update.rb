# frozen_string_literal: true

require_relative "../codec"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    # `request_update` is kept as received; a value other than 0 or 1 is a
    # violation that `#validate` reports, not a parse error.
    class KeyUpdate < Data.define(:request_update)
      include Message

      MSG_TYPE = 24

      UPDATE_NOT_REQUESTED = 0
      UPDATE_REQUESTED = 1

      def self.parse_body(body, registry: nil)
        r = Codec::Reader.new(body)
        request_update = r.u8
        r.finish!
        new(request_update:)
      end

      def msg_type = MSG_TYPE

      def validate
        return nil if request_update == UPDATE_NOT_REQUESTED || request_update == UPDATE_REQUESTED
        Violation.new(alert: :illegal_parameter, reason: :request_update)
      end

      def write_body(w)
        w.u8(request_update)
      end
    end
  end
end
