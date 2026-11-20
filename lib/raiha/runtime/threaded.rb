# frozen_string_literal: true

require "monitor"

module Raiha::Runtime
  # The runtime on threads, with no Fiber scheduler: the classes of
  # Raiha::Runtime by the same names, to be called from any thread. Where
  # the runtime of fibers starts a fiber, this one starts a thread: the
  # reader of each socket and the runner of a driver, the handler of each
  # connection, each stream of `each_stream` and each request of HTTP/3.
  #
  # A fiber runs until it yields, so the runtime of fibers calls into the
  # core with no lock. A thread can be preempted anywhere, so each Driver
  # here has a lock, a Monitor, that whatever touches its Endpoint, its
  # connections, their HTTP/3 or what a Session keeps takes first; no I/O
  # and no application code runs under it, and what waits waits on a
  # condition of it. The runtime of fibers and this one are not to be
  # mixed in one connection.
  module Threaded
  end
end

require_relative "threaded/driver"
require_relative "threaded/session"
