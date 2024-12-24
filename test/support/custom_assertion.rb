require "minitest/assertions"

module Minitest::Assertions
  def assert_equal_bin(expected, actual)
    msg = message(msg) {
      formatted_expected = expected.unpack1("H*").scan(/../).join(" ").gsub(/.{60}/, "\\0\n")
      formatted_actual = actual.unpack1("H*").scan(/../).join(" ").gsub(/.{60}/, "\\0\n")
      "Expected:\n#{formatted_expected}\n\nActual:\n#{formatted_actual}\n"
    }
    assert((expected == actual), msg)
  end
end
