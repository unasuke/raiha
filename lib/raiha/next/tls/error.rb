# frozen_string_literal: true

module Raiha::Next::TLS
  # Misuse of the API by the caller, as opposed to bad bytes from the peer,
  # which never raise.
  class UsageError < StandardError; end
end
