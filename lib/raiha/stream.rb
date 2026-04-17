# frozen_string_literal: true

require_relative "../raiha"

module Raiha
  class Stream
    module SendState
      READY = :ready
      SEND = :send
      DATA_SENT = :data_sent
      RESET_SENT = :reset_sent
    end

    module ReceiveState
      RECV = :recv
      SIZE_KNOWN = :size_known
      DATA_RECVD = :data_recvd
      DATA_READ = :data_read
      RESET_RECVD = :reset_recvd
    end

    attr_reader :stream_id
    attr_reader :send_state
    attr_reader :receive_state
    attr_reader :flow_controller

    def fin_received?
      @fin_received
    end

    # Tell the flow controller to raise the send window limit (e.g. from MAX_STREAM_DATA).
    def update_send_window(max)
      @flow_controller.update_send_window(max)
    end

    def initialize(stream_id:, flow_controller:)
      @stream_id = stream_id
      @flow_controller = flow_controller

      @send_state = SendState::READY
      @receive_state = ReceiveState::RECV

      @send_buffer = SendBuffer.new
      @send_offset = 0
      @fin_sent = false

      @receive_buffer = ReceiveBuffer.new
      @read_offset = 0
      @fin_received = false

      @on_data_available = nil
    end

    def write(data)
      raise Raiha::Error, "Stream not writable" unless writable?

      @send_buffer.push(data, @send_offset)
      @send_offset += data.bytesize
      @send_state = SendState::SEND
    end

    def close_write
      @fin_sent = true
      @send_state = SendState::DATA_SENT
    end

    def read(max_bytes = nil)
      raise Raiha::Error, "Stream not readable" unless readable?

      data = @receive_buffer.read(@read_offset, max_bytes)
      @read_offset += data.bytesize
      @flow_controller.add_bytes_read(data.bytesize)

      if @fin_received && @read_offset >= @receive_buffer.final_offset
        @receive_state = ReceiveState::DATA_READ
      end

      data
    end

    def data_available?
      @receive_buffer.has_data_at?(@read_offset)
    end

    def writable?
      @send_state == SendState::READY || @send_state == SendState::SEND
    end

    def readable?
      [ReceiveState::RECV, ReceiveState::SIZE_KNOWN, ReceiveState::DATA_RECVD].include?(@receive_state)
    end

    def receive_data(offset, data, fin: false)
      @flow_controller.update_highest_received(offset, data.bytesize)
      @receive_buffer.push(data, offset)

      if fin
        @fin_received = true
        final_offset = offset + data.bytesize
        @flow_controller.set_final_size(final_offset)
        @receive_buffer.set_final_offset(final_offset)
        @receive_state = ReceiveState::SIZE_KNOWN

        if @read_offset >= final_offset
          @receive_state = ReceiveState::DATA_RECVD
        end
      end

      @on_data_available&.call(self) if data_available?
    end

    def get_data_to_send(max_bytes)
      return nil unless @send_buffer.has_data?

      allowed = @flow_controller.send_window_size
      bytes_to_send = [max_bytes, allowed, @send_buffer.pending_bytes].min
      return nil if bytes_to_send == 0

      data = @send_buffer.pop(bytes_to_send)
      @flow_controller.add_bytes_sent(data.bytesize)

      {
        offset: @send_buffer.sent_offset - data.bytesize,
        data: data,
        fin: @fin_sent && @send_buffer.empty?,
      }
    end

    def on_data(&block)
      @on_data_available = block
    end
  end

  class Stream::SendBuffer
    attr_reader :sent_offset

    def initialize
      @chunks = [] #: Array[Hash[Symbol, untyped]]
      @sent_offset = 0
    end

    def push(data, offset)
      @chunks << { offset: offset, data: data }
    end

    def pop(max_bytes)
      return "".b if @chunks.empty?

      result = String.new(encoding: "BINARY")
      while !@chunks.empty? && result.bytesize < max_bytes
        chunk = @chunks.first
        remaining = max_bytes - result.bytesize
        to_take = [chunk[:data].bytesize, remaining].min

        result << chunk[:data][0, to_take]

        if to_take == chunk[:data].bytesize
          @chunks.shift
        else
          chunk[:data] = chunk[:data][to_take..]
          chunk[:offset] += to_take
        end
      end

      @sent_offset += result.bytesize
      result
    end

    def has_data?
      !@chunks.empty?
    end

    def pending_bytes
      @chunks.sum { |chunk| chunk[:data].bytesize }
    end

    def empty?
      @chunks.empty?
    end
  end

  class Stream::ReceiveBuffer
    attr_reader :final_offset

    def initialize
      @chunks = {} #: Hash[Integer, String]
      @final_offset = nil
    end

    def push(data, offset)
      @chunks[offset] = data
      merge_chunks
    end

    def read(offset, max_bytes)
      return "".b unless has_data_at?(offset)

      chunk_offset, chunk_data = @chunks.find { |start_offset, data| start_offset <= offset && start_offset + data.bytesize > offset }
      return "".b unless chunk_data

      start_in_chunk = offset - chunk_offset
      available = chunk_data.bytesize - start_in_chunk
      to_read = max_bytes ? [available, max_bytes].min : available

      chunk_data[start_in_chunk, to_read]
    end

    def has_data_at?(offset)
      @chunks.any? { |start_offset, data| start_offset <= offset && start_offset + data.bytesize > offset }
    end

    def set_final_offset(offset)
      @final_offset = offset
    end

    private def merge_chunks
      sorted = @chunks.sort_by { |start_offset, _| start_offset }
      merged = {} #: Hash[Integer, String]

      sorted.each do |offset, data|
        if merged.empty?
          merged[offset] = data
        else
          last_offset, last_data = merged.to_a.last
          if last_offset + last_data.bytesize >= offset
            overlap = last_offset + last_data.bytesize - offset
            if overlap < data.bytesize
              merged[last_offset] = last_data + data[overlap..]
            end
          else
            merged[offset] = data
          end
        end
      end

      @chunks = merged
    end
  end
end
