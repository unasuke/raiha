require "test_helper"
require "raiha"

# The way into either runtime: the namespace Raiha::Runtime.for gives, the
# runtime of fibers unless the runtime on threads is asked for.
class RaihaRuntimeForTest < Minitest::Test
  def test_the_namespace_of_each_concurrency
    assert_same Raiha::Runtime, Raiha::Runtime.for
    assert_same Raiha::Runtime, Raiha::Runtime.for(concurrency: :fiber)
    assert_same Raiha::Runtime::Threaded, Raiha::Runtime.for(concurrency: :thread)
    assert_same Raiha::Runtime::Threaded::Server, Raiha::Runtime.for(concurrency: :thread)::Server
  end

  def test_any_other_concurrency
    ["thread", nil, :threads, :ractor].each do |concurrency|
      error = assert_raises(ArgumentError) { Raiha::Runtime.for(concurrency:) }
      assert_equal "concurrency is :fiber or :thread, not #{concurrency.inspect}", error.message
    end
  end
end
