# frozen_string_literal: true

module Raiha::Runtime
  module HTTP3
    # How the HTTP/3 of the runtime puts the fields of a request and a
    # response together and takes them apart, apart from how it waits. The
    # HTTP/3 of fibers and that of threads do it alike.
    module Fields
      # The pseudo-header fields of `headers` by name, and the other fields
      # in their order.
      def self.split(headers)
        pseudo, fields = headers.partition { |name, _| name.start_with?(":") }
        [pseudo.to_h, fields] #: [Hash[String, String], Array[[String, String]]]
      end

      # The pseudo-header fields of a request of `method` for `path` at
      # `authority`, over https.
      def self.request(method, authority, path)
        [[":method", method], [":scheme", "https"], [":authority", authority], [":path", path]] #: Array[[String, String]]
      end

      # The `priority` field (RFC 9218) of `urgency` (0 to 7) and
      # `incremental`; none when neither is given.
      def self.priority(urgency, incremental)
        raise ArgumentError, "an urgency is 0 to 7, not #{urgency.inspect}" unless urgency.nil? || (urgency.is_a?(Integer) && urgency.between?(0, 7))
        parameters = [("u=#{urgency}" if urgency), ("i" if incremental)].compact
        parameters.empty? ? [] : [["priority", parameters.join(", ")]]
      end

      # The status of a response's header section `headers`, 0 when it has
      # none; nil for an interim response (1xx), which is let go.
      def self.status(headers)
        status = headers.find { |name, _| name == ":status" }&.last.to_i
        status unless status.between?(100, 199)
      end
    end
  end
end
