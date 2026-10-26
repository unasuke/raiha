# frozen_string_literal: true

require_relative "structured_field"

module Raiha::Next::HTTP3
  # The checks of RFC 9114 "Malformed Requests and Responses" on the field
  # sections of a message: what fields and pseudo-header fields it holds,
  # in what order, and with what names and values. A message that fails
  # one is a stream error of type H3_MESSAGE_ERROR.
  module Message
    # A field section that fails a check.
    class Malformed < StandardError; end

    REQUEST_PSEUDO = %w[:method :scheme :authority :path :protocol].freeze
    RESPONSE_PSEUDO = %w[:status].freeze
    # RFC 9114 "HTTP Fields": these hold for one connection only, and are
    # never in an HTTP/3 message; TE is, in a request, as "trailers".
    CONNECTION_SPECIFIC = %w[connection keep-alive proxy-connection transfer-encoding upgrade].freeze
    # A token of RFC 9110 "Field Names" in lowercase, after a ":" for a
    # pseudo-header field.
    NAME = /\A:?[!#$%&'*+\-.^_`|~0-9a-z]+\z/n
    # What never goes in a field value (RFC 9110 "Field Values").
    NOT_IN_VALUE = /[\x00\r\n]/n
    SCHEMES_WITH_AUTHORITY = %w[http https].freeze
    STATUS = /\A[1-5][0-9][0-9]\z/n

    # Checks the header section of a request: its Content-Length, if it has
    # one. `extended_connect` is whether this end took Extended CONNECT
    # (RFC 9220), for :protocol.
    def self.request(headers, extended_connect:)
      pseudo = pseudo_header_fields(headers, REQUEST_PSEUDO, request: true)
      method = pseudo[":method"] or raise Malformed, "no :method"
      if pseudo.key?(":protocol")
        raise Malformed, ":protocol, with Extended CONNECT not taken" unless extended_connect
        raise Malformed, ":protocol with #{method}" unless method == "CONNECT"
        %w[:scheme :path :authority].each { |name| raise Malformed, "Extended CONNECT with no #{name}" unless pseudo.key?(name) }
      elsif method == "CONNECT"
        raise Malformed, "CONNECT with :scheme or :path" if pseudo.key?(":scheme") || pseudo.key?(":path")
        raise Malformed, "CONNECT with no :authority" unless pseudo[":authority"]&.then { !_1.empty? }
        return content_length(headers)
      else
        %w[:scheme :path].each { |name| raise Malformed, "no #{name}" unless pseudo.key?(name) }
      end
      authority(headers, pseudo)
      content_length(headers)
    end

    # Checks the header section of a response: its status and its
    # Content-Length, if it has one.
    def self.response(headers)
      status = pseudo_header_fields(headers, RESPONSE_PSEUDO, request: false)[":status"] or raise Malformed, "no :status"
      raise Malformed, ":status #{status.inspect}" unless STATUS.match?(status)
      [Integer(status, 10), content_length(headers)]
    end

    # Whether the message of `headers` says it uses the Capsule Protocol
    # (RFC 9297 "The Capsule-Protocol Header Field"): one Capsule-Protocol
    # field, an Item that is true; one of another type is as none. Such a
    # message carries no Content-Length nor Content-Type, and a response
    # using it, as `status` says, is none of 204, 205 and 206 ("The Capsule
    # Protocol").
    def self.capsule_protocol?(headers, status: nil)
      values = headers.filter_map { |name, value| value if name == "capsule-protocol" }
      return false unless values.size == 1 && StructuredField.item(values.first) == true
      if headers.any? { |name, _| name == "content-length" || name == "content-type" }
        raise Malformed, "the Capsule Protocol with content"
      end
      raise Malformed, "the Capsule Protocol on a #{status}" if [204, 205, 206].include?(status)
      true
    end

    # Checks a trailer section, which has no pseudo-header field.
    def self.trailers(headers)
      pseudo_header_fields(headers, [], request: false)
      nil
    end

    # The pseudo-header fields of `headers`, among `allowed`, each once and
    # before the fields, by name; every name and value checked on the way.
    def self.pseudo_header_fields(headers, allowed, request:)
      pseudo = {} #: Hash[String, String]
      regular = false
      headers.each do |name, value|
        raise Malformed, "the name #{name.inspect}" unless NAME.match?(name)
        raise Malformed, "the value of #{name}" if NOT_IN_VALUE.match?(value)
        if name.start_with?(":")
          raise Malformed, "#{name} after a field" if regular
          raise Malformed, "#{name}, not of this message" unless allowed.include?(name)
          raise Malformed, "#{name} twice" if pseudo.key?(name)
          pseudo[name] = value
        else
          regular = true
          raise Malformed, "the field #{name}, of one connection" if CONNECTION_SPECIFIC.include?(name)
          raise Malformed, "te: #{value}" if name == "te" && !(request && value == "trailers")
        end
      end
      pseudo
    end

    # RFC 9114 "Request Pseudo-Header Fields": a scheme that has an
    # authority needs :authority or Host, not empty, the same if both, with
    # no userinfo.
    def self.authority(headers, pseudo)
      return unless SCHEMES_WITH_AUTHORITY.include?(pseudo[":scheme"])
      raise Malformed, "an empty :path" if pseudo[":path"]&.empty?
      hosts = headers.filter_map { |name, value| value if name == "host" }
      raise Malformed, "Host #{hosts.size} times" if hosts.size > 1
      authority = pseudo[":authority"]
      host = hosts.first
      raise Malformed, "no :authority nor Host" if authority.nil? && host.nil?
      raise Malformed, "an empty :authority or Host" if authority&.empty? || host&.empty?
      raise Malformed, ":authority and Host differ" if authority && host && authority != host
      raise Malformed, "userinfo in the authority" if (authority || host)&.include?("@")
    end

    # The value of Content-Length, the same in every field line; nil when
    # there is none.
    def self.content_length(headers)
      values = headers.filter_map { |name, value| value if name == "content-length" }
      return nil if values.empty?
      raise Malformed, "Content-Length #{values.uniq.inspect}" unless values.uniq.size == 1 && values.first.match?(/\A[0-9]{1,19}\z/n)
      Integer(values.first, 10)
    end

    private_class_method :pseudo_header_fields, :authority, :content_length
  end
end
