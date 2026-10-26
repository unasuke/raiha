require "raiha/next/test_helper"
require "raiha/next/http3"

# Dictionaries of Structured Field Values (RFC 8941), as Priority carries
# them.
class RaihaNextHTTP3StructuredFieldTest < Minitest::Test
  StructuredField = Raiha::Next::HTTP3::StructuredField

  def test_the_priority_of_rfc_9218
    assert_equal({ "u" => 5, "i" => true }, StructuredField.dictionary("u=5, i"))
  end

  def test_every_type_of_item
    text = 'a=-12, b=1.5, c="say \"hi\"", d=:aGVsbG8=:, e=?0, f=?1, g=text/html, h=(1 "x" y), i'
    assert_equal(
      { "a" => -12, "b" => 1.5, "c" => 'say "hi"', "d" => "hello", "e" => false, "f" => true, "g" => :"text/html", "h" => [1, "x", :y], "i" => true },
      StructuredField.dictionary(text)
    )
  end

  # Parameters are read and dropped; a key that repeats keeps its last.
  def test_parameters_and_keys_that_repeat
    assert_equal({ "u" => 2, "i" => true }, StructuredField.dictionary("u=1;a=?1, i;b=2;c, u=2;d=\"x\""))
    assert_equal({ "l" => [1] }, StructuredField.dictionary("l=( 1 );q=0.5"))
  end

  def test_white_space
    assert_equal({ "u" => 1, "i" => true }, StructuredField.dictionary("  u=1 ,\ti"))
    assert_equal({}, StructuredField.dictionary(""))
  end

  def test_what_is_not_a_dictionary
    [
      "U=1", "1=2", "u=1,", "u=1 i", "u=", 'u="open', "u=1234567890123456", "u=1.2345", "u=(1", "u=(1,2)",
      "u=é", "u=?2", "u=1;", "u=1; =2", "u=:a*b:", "u=1 , ", ",u=1"
    ].each { |text| assert_nil StructuredField.dictionary(text), text }
  end
end
