# frozen_string_literal: true

require_relative "tls"
require_relative "quic"
require_relative "http3"

# The I/O runtime (Fiber, Ractor, Socket). May refer to TLS, QUIC and HTTP/3.
module Raiha::Runtime
  # The namespace of the runtime that runs with `concurrency`: Raiha::Runtime
  # itself for :fiber, the default, whose clients and servers wait through a
  # Fiber scheduler, and Raiha::Runtime::Threaded for :thread, whose run on
  # threads of their own. Both have Server, Client, Session and HTTP3 by the
  # same names.
  def self.for(concurrency: :fiber)
    case concurrency
    when :fiber then self
    when :thread then Threaded
    else raise ArgumentError, "concurrency is :fiber or :thread, not #{concurrency.inspect}"
    end
  end
end

require_relative "runtime/error"
require_relative "runtime/udp"
require_relative "runtime/driver"
require_relative "runtime/worker"
require_relative "runtime/workers"
require_relative "runtime/qlog"
require_relative "runtime/admission"
require_relative "runtime/addresses"
require_relative "runtime/kept"
require_relative "runtime/session"
require_relative "runtime/client"
require_relative "runtime/server"
require_relative "runtime/http3"
require_relative "runtime/http3_server"
require_relative "runtime/threaded"
