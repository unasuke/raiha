# frozen_string_literal: true

require_relative "varint"

module Raiha::Next::HTTP3
  # The frames of HTTP/3 (RFC 9114 "Frame Definitions"), and those of
  # PRIORITY_UPDATE (RFC 9218 "HTTP/3 PRIORITY_UPDATE Frame"): a type and
  # a length, both varints, then the payload. Values in, bytes out, and
  # back; which stream a frame may go on is not decided here.
  module Frame
    DATA = 0x00
    HEADERS = 0x01
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0d
    # For a request stream, and for a push.
    PRIORITY_UPDATE = 0xf0700
    PRIORITY_UPDATE_PUSH = 0xf0701
    # The types of HTTP/2's PRIORITY, PING, WINDOW_UPDATE and CONTINUATION,
    # which HTTP/3 reserves and never takes (RFC 9114 "Reserved Frame
    # Types").
    HTTP2_TYPES = [0x02, 0x06, 0x08, 0x09].freeze

    # A payload that does not hold exactly the fields of its frame (RFC
    # 9114 "Frame Layout"): H3_FRAME_ERROR, raised here and turned into the
    # closing of the connection where the bytes came in.
    class Malformed < StandardError; end

    # The Strings of a frame are frozen and binary, copied first when the
    # caller's are not.
    def self.binary(string) = string.frozen? && string.encoding == Encoding::BINARY ? string : string.b.freeze

    class Data < ::Data.define(:data)
      def initialize(data:)
        data = Frame.binary(data)
        super
      end
    end

    # An encoded field section, as QPACK gives and takes it.
    class Headers < ::Data.define(:field_section)
      def initialize(field_section:)
        field_section = Frame.binary(field_section)
        super
      end
    end

    class CancelPush < ::Data.define(:push_id); end

    # The identifiers and values, in the order they came, each pair once or
    # more: whether one repeats is for the reader of SETTINGS to say.
    class Settings < ::Data.define(:settings)
      def initialize(settings:)
        settings = Ractor.make_shareable(settings.map(&:dup))
        super
      end
    end

    class PushPromise < ::Data.define(:push_id, :field_section)
      def initialize(push_id:, field_section:)
        field_section = Frame.binary(field_section)
        super
      end
    end

    # A stream ID from a server, a push ID from a client.
    class GoAway < ::Data.define(:id); end

    class MaxPushId < ::Data.define(:push_id); end

    # `priority` is the Priority Field Value, the ASCII text of the
    # Priority header field; `push` whether `element_id` is a push ID
    # rather than a stream ID.
    class PriorityUpdate < ::Data.define(:element_id, :priority, :push)
      def initialize(element_id:, priority:, push: false)
        priority = Frame.binary(priority)
        super
      end
    end

    # The type and length that go before a payload of `length` bytes.
    def self.header(type, length) = Varint.encode(type) << Varint.encode(length)

    # `frame` as it goes on a stream.
    def self.encode(frame)
      type, payload = case frame
        in Data then [DATA, frame.data]
        in Headers then [HEADERS, frame.field_section]
        in CancelPush then [CANCEL_PUSH, Varint.encode(frame.push_id)]
        in Settings then [SETTINGS, frame.settings.map { |identifier, value| Varint.encode(identifier) << Varint.encode(value) }.join]
        in PushPromise then [PUSH_PROMISE, Varint.encode(frame.push_id) << frame.field_section]
        in GoAway then [GOAWAY, Varint.encode(frame.id)]
        in MaxPushId then [MAX_PUSH_ID, Varint.encode(frame.push_id)]
        in PriorityUpdate then [frame.push ? PRIORITY_UPDATE_PUSH : PRIORITY_UPDATE, Varint.encode(frame.element_id) << frame.priority]
      end
      header(type, payload.bytesize) << payload
    end

    # The frame of `type` whose payload is `payload`, whole. Malformed when
    # the payload holds less or more than the frame's fields.
    def self.decode(type, payload)
      case type
      when DATA then Data.new(data: payload)
      when HEADERS then Headers.new(field_section: payload)
      when CANCEL_PUSH then CancelPush.new(push_id: only_varint(payload))
      when SETTINGS then Settings.new(settings: pairs(payload))
      when PUSH_PROMISE
        push_id, offset = varint(payload, 0)
        PushPromise.new(push_id:, field_section: payload.byteslice(offset..)) # steep:ignore
      when GOAWAY then GoAway.new(id: only_varint(payload))
      when MAX_PUSH_ID then MaxPushId.new(push_id: only_varint(payload))
      when PRIORITY_UPDATE, PRIORITY_UPDATE_PUSH
        element_id, offset = varint(payload, 0)
        PriorityUpdate.new(element_id:, priority: payload.byteslice(offset..), push: type == PRIORITY_UPDATE_PUSH) # steep:ignore
      else raise ArgumentError, "no frame of type 0x#{type.to_s(16)} to decode"
      end
    end

    def self.varint(payload, offset)
      Varint.decode(payload, offset) or raise Malformed, "a varint is cut short"
    end

    # The one varint `payload` holds, and nothing more.
    def self.only_varint(payload)
      value, offset = varint(payload, 0)
      raise Malformed, "#{payload.bytesize - offset} bytes past the end" unless offset == payload.bytesize
      value
    end

    def self.pairs(payload)
      settings = [] #: Array[[Integer, Integer]]
      offset = 0
      while offset < payload.bytesize
        identifier, offset = varint(payload, offset)
        value, offset = varint(payload, offset)
        settings << [identifier, value]
      end
      settings
    end

    private_class_method :varint, :only_varint, :pairs
  end
end
