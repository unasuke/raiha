# frozen_string_literal: true

require "test_helper"
require "stringio"
require "raiha/util/io_reader"

class RaihaUtilIOReaderTest < Minitest::Test
  def test_read_exact_returns_exact_bytes
    io = StringIO.new("hello world")
    assert_equal "hello", Raiha::Util::IOReader.read_exact(io, 5)
    assert_equal " worl", Raiha::Util::IOReader.read_exact(io, 5)
  end

  def test_read_exact_raises_on_eof
    io = StringIO.new("")
    assert_raises(EOFError) do
      Raiha::Util::IOReader.read_exact(io, 1)
    end
  end

  def test_read_exact_raises_when_short_read
    io = StringIO.new("ab")
    assert_raises(EOFError) do
      Raiha::Util::IOReader.read_exact(io, 4)
    end
  end

  def test_read_exact_zero_length_returns_empty_string
    io = StringIO.new("data")
    assert_equal "", Raiha::Util::IOReader.read_exact(io, 0)
  end
end
