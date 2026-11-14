# frozen_string_literal: true

require_relative "masked_inspect"

module Raiha::TLS
  # What the handshake core hands to its transport, in one ordered queue.
  #
  # A Secret comes out when its key may be used, and every Message and Alert
  # carries the epoch whose key sends it, so the consumer only has to handle
  # the queue in order. Within one trigger the Secrets that became usable
  # come before the Messages. The one exception is a TCP KeyUpdate, sent
  # under the old key and followed by the new write Secret.
  module Output
    # One handshake message, header included.
    class Message < Data.define(:epoch, :bytes)
    end

    # A traffic secret, not a key: QUIC derives its own keys from it with
    # labels of its own. `direction` is :read or :write; `cipher_suite` is the
    # CipherSuite descriptor.
    class Secret < Data.define(:epoch, :direction, :secret, :cipher_suite)
      include MaskedInspect

      def masked_members = %i[secret]
    end

    # `epoch` is the write epoch when the alert was raised, the one the peer
    # is reading.
    class Alert < Data.define(:level, :description, :epoch)
    end
  end
end
