require "test_helper"
require "raiha/http3"

# The priority parameters of RFC 9218.
class RaihaHTTP3PriorityTest < Minitest::Test
  Priority = Raiha::HTTP3::Priority

  def priority(urgency, incremental) = Priority.new(urgency:, incremental:)

  def test_the_defaults
    assert_equal priority(3, false), Priority.new
    assert_equal priority(3, false), Priority.parse("")
  end

  def test_what_a_field_asks_for
    assert_equal priority(0, false), Priority.parse("u=0")
    assert_equal priority(5, true), Priority.parse("u=5, i")
    assert_equal priority(3, true), Priority.parse("i=?1")
  end

  # "Priority Parameters": out of range, of another type, or not known,
  # a parameter is ignored; a field that is no Dictionary gives the
  # defaults.
  def test_what_is_ignored
    assert_equal priority(3, true), Priority.parse("u=8, i")
    assert_equal priority(3, false), Priority.parse("u=1.0, i=1")
    assert_equal priority(2, false), Priority.parse("u=2, x=?1, i=(1)")
    assert_equal priority(3, false), Priority.parse("u=1;")
    assert_equal [nil, nil], Priority.parameters("x")
    assert_nil Priority.parameters("u=1;")
  end

  # "Merging Client- and Server-Driven Priority Parameters": what a
  # response leaves out stays as the request asked.
  def test_merging
    assert_equal priority(1, true), priority(5, true).merge(*Priority.parameters("u=1"))
    assert_equal priority(5, false), priority(5, true).merge(nil, false)
  end

  def test_the_field_that_gives_one
    assert_equal ["", "u=0, i", "i", "u=7"], [priority(3, false), priority(0, true), priority(3, true), priority(7, false)].map(&:to_field)
  end

  def test_arguments_are_checked
    assert_raises(ArgumentError) { Priority.new(urgency: 8) }
    assert_raises(ArgumentError) { Priority.new(incremental: nil) }
    assert Ractor.shareable?(Priority.parse("u=1, i"))
  end
end
