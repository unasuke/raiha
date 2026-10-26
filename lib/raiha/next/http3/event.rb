# frozen_string_literal: true

module Raiha::Next::HTTP3
  # What happened on an HTTP/3 connection, for the application.
  module Event
    # The peer's settings came (Settings).
    class Settings < Data.define(:settings); end
  end
end
