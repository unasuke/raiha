# frozen_string_literal: true

require "stringio"

module Raiha
  module TLS
    class Record
      CONTENT_TYPE = {
        invalid: 0,
        change_cipher_spec: 20,
        alert: 21,
        handshake: 22,
        application_data: 23,
      }.freeze
      LEGACY_RECORD_VERSION = [0x03, 0x03].pack("C*") # TLS v1.2
    end
  end
end
