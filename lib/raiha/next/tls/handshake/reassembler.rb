# frozen_string_literal: true

module Raiha::Next::TLS
  module Handshake
    # Rebuilds handshake messages from the bytes of one epoch, which may split
    # a message anywhere or carry several in one piece. One per epoch.
    #
    # The 4-byte header of each message is checked as soon as it is complete,
    # before its body is buffered: a type outside the set given to `#expect`
    # is `:unexpected`, and a length above the limit for its type is
    # `:overflow`. So an unexpected Certificate never costs 256 KiB, and an
    # unknown type never reaches the parser.
    #
    # The state machine changes what it expects after every message, so only
    # the next header is checked at a time: `#<<` checks it when the bytes
    # arrive, and `#each_message` checks each following one after yielding
    # the message before it. Both return `:ok`, `:overflow` or `:unexpected`.
    # A failure is final; later calls return it again and yield nothing.
    class Reassembler
      def initialize(limits:)
        @limits = limits
        @expected = Set.new #: Set[Integer]
        @buf = String.new(encoding: Encoding::BINARY)
        @header_checked = false
        @status = :ok #: :ok | :overflow | :unexpected
      end

      # The message types acceptable next, from the state machine's table of
      # expected messages.
      def expect(types)
        @expected = types
        nil
      end

      def <<(bytes)
        return @status unless @status == :ok
        @buf << bytes
        check_header
      end

      # Yields `(msg_type, body)` for every complete message, in order.
      def each_message
        loop do
          status = check_header
          return status unless status == :ok
          length = message_length
          break if length.nil? || @buf.bytesize < 4 + length
          msg_type = @buf.getbyte(0) #: Integer
          body = @buf.byteslice(4, length).freeze # steep:ignore
          @buf = @buf.byteslice(4 + length, @buf.bytesize) # steep:ignore
          @header_checked = false
          yield msg_type, body
        end
        :ok
      end

      # Whether any bytes wait: part of a message, or whole messages not yet
      # taken by `#each_message`. The state machine must not move to the next
      # epoch while this is true.
      def pending? = !@buf.empty?

      # The type of the next message, once its first byte is here: after an
      # `:unexpected`, the type that was not expected.
      def next_type = @buf.getbyte(0)

      private def check_header
        return @status unless @status == :ok
        return :ok if @header_checked
        length = message_length
        return :ok if length.nil?
        msg_type = @buf.getbyte(0) #: Integer
        if !@expected.include?(msg_type)
          @status = :unexpected
        elsif length > @limits.call(msg_type)
          @status = :overflow
        else
          @header_checked = true
          :ok
        end
      end

      private def message_length
        return nil if @buf.bytesize < 4
        (@buf.getbyte(1) << 16) | (@buf.getbyte(2) << 8) | @buf.getbyte(3) # steep:ignore
      end
    end
  end
end
