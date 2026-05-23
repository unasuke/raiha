# frozen_string_literal: true

module Raiha
  module Util
    module IOReader
      module_function

      def read_exact(io, n)
        bytes = io.read(n)
        raise EOFError, "expected #{n} byte(s), got EOF" if bytes.nil? || bytes.bytesize < n
        bytes
      end
    end
  end
end
