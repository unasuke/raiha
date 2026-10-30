# frozen_string_literal: true

require_relative "namespace"

# TLS 1.3. Depends on nothing but openssl.
module Raiha::Next::TLS
end

require_relative "tls/codec"
require_relative "tls/iana"
require_relative "tls/crypto"
require_relative "tls/error"
require_relative "tls/key_schedule"
require_relative "tls/keylog"
require_relative "tls/transcript"
require_relative "tls/cipher_suite"
require_relative "tls/signature_scheme"
require_relative "tls/key_exchange"
require_relative "tls/extension"
require_relative "tls/handshake"
require_relative "tls/profile"
require_relative "tls/output"
require_relative "tls/event"
require_relative "tls/trace"
require_relative "tls/ticket_keys"
require_relative "tls/ticket"
require_relative "tls/session"
require_relative "tls/config"
require_relative "tls/verifier"
require_relative "tls/keyring"
require_relative "tls/server_name"
require_relative "tls/record"
require_relative "tls/tcp"
