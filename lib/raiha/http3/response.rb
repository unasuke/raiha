# frozen_string_literal: true

module Raiha
  module HTTP3
    class Response
      attr_accessor :headers, :body

      def initialize(headers: [], body: "".b)
        @headers = headers
        @body = body
      end

      def status
        @headers.each { |n, v| return v.to_i if n == ":status" }
        nil
      end
    end
  end
end
