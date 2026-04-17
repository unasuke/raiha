# frozen_string_literal: true

module Raiha
  module HTTP3
    # RFC 9114 Section 6.2: Unidirectional stream types
    module StreamType
      CONTROL = 0x00
      PUSH = 0x01
      # RFC 9204 Section 4.2: QPACK streams
      QPACK_ENCODER = 0x02
      QPACK_DECODER = 0x03
    end
  end
end
