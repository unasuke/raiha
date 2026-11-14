# frozen_string_literal: true

module Raiha::TLS
  module TCP
    # What TCP::Connection tells the application on top of the Machine's
    # events. Alerts never reach the Machine, so these are the binding's.
    module Event
      # An alert the peer sent. Both values are the peer's, so they stay
      # Integers: the description may be one this implementation does not
      # know (IANA.alert_name names the known ones).
      class PeerAlert < Data.define(:level, :description)
      end
    end
  end
end
