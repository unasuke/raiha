# frozen_string_literal: true

module Raiha
  module HTTP3
    class Request
      attr_accessor :headers, :body

      def initialize(headers: [], body: "".b)
        @headers = headers
        @body = body
      end

      def method
        find_pseudo_header(":method")
      end

      def path
        find_pseudo_header(":path")
      end

      def scheme
        find_pseudo_header(":scheme")
      end

      def authority
        find_pseudo_header(":authority")
      end

      private def find_pseudo_header(name)
        @headers.each { |n, v| return v if n == name }
        nil
      end
    end
  end
end
