# frozen_string_literal: true

require_relative "../raiha"
require_relative "quic/wire/frames/reset_stream_frame"
require_relative "quic/wire/frames/stop_sending_frame"

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
    attr_reader :peer_reset_error_code
    attr_reader :peer_reset_final_size
    attr_reader :local_reset_error_code

    def fin_received?
      @fin_received
    end

    def reset_received?
      @receive_state == ReceiveState::RESET_RECVD
    end

    def reset_sent?
      @send_state == SendState::RESET_SENT
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

      # Error codes are only meaningful when the corresponding state flag
      # says so (reset_sent? / reset_received?); defaulting to 0 keeps these
      # ivars typed as Integer without nil-narrowing gymnastics at each use.
      @local_reset_error_code = 0
      @peer_reset_error_code = 0
      @peer_reset_final_size = 0
      @stop_sending_error_code = 0
      @send_final_size = 0
      @pending_reset_stream = false
      @pending_stop_sending = false

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
      # RFC 9000 §3.2: once receive side enters Reset Recvd, STREAM frames MUST be discarded.
      return if reset_received?

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

    # Abort sending on this stream (RFC 9000 §3.5, §19.4). Transitions to
    # Reset Sent, pins the final size to the highest offset already handed
    # to the send buffer, drops anything still pending, and queues a
    # RESET_STREAM frame for the connection to emit.
    def reset(error_code)
      return if reset_sent?

      @local_reset_error_code = error_code
      @send_final_size = @send_offset
      @send_state = SendState::RESET_SENT
      @send_buffer.clear
      @pending_reset_stream = true
    end

    # Peer reset our receive side (RFC 9000 §3.2). Transition to Reset Recvd,
    # remember the reported error code and final size, and drop anything
    # buffered but not yet read.
    def handle_reset_stream(error_code:, final_size:)
      return if reset_received?

      @peer_reset_error_code = error_code
      @peer_reset_final_size = final_size
      @receive_state = ReceiveState::RESET_RECVD
      @receive_buffer.clear
    end

    # Ask the peer to stop sending on this stream (RFC 9000 §3.5, §19.5).
    def stop_sending(error_code)
      return if reset_received?
      return if @pending_stop_sending

      @stop_sending_error_code = error_code
      @pending_stop_sending = true
    end

    # Peer sent STOP_SENDING. RFC 9000 §3.5: when the send side is in Ready
    # or Send, we MUST send RESET_STREAM using the same error code. If we
    # already reset, or we already sent the FIN, there is nothing to do.
    def handle_stop_sending(error_code)
      return if reset_sent?
      return if @send_state == SendState::DATA_SENT

      reset(error_code)
    end

    # Returns a RESET_STREAM frame and clears the pending flag, or nil.
    def take_reset_stream_frame
      return nil unless @pending_reset_stream

      frame = Raiha::Quic::Wire::Frames::ResetStreamFrame.new
      frame.stream_id = @stream_id.value
      frame.application_protocol_error_code = @local_reset_error_code
      frame.final_size = @send_final_size
      @pending_reset_stream = false
      frame
    end

    # Returns a STOP_SENDING frame and clears the pending flag, or nil.
    def take_stop_sending_frame
      return nil unless @pending_stop_sending

      frame = Raiha::Quic::Wire::Frames::StopSendingFrame.new
      frame.stream_id = @stream_id.value
      frame.application_protocol_error_code = @stop_sending_error_code
      @pending_stop_sending = false
      frame
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

    def clear
      @chunks = [] #: Array[Hash[Symbol, untyped]]
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

    def clear
      @chunks = {} #: Hash[Integer, String]
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
