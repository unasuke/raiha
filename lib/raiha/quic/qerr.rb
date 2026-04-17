# frozen_string_literal: true

module Raiha::Quic
  module Qerr
  end
end

require_relative "error"
require_relative "qerr/error_code"
require_relative "qerr/transport_error"
require_relative "qerr/application_error"
