require "test_helper"
require "raiha/http3/qpack"

# RFC 9204 Appendix A.
class RaihaNextQPACKStaticTableTest < Minitest::Test
  StaticTable = Raiha::Next::HTTP3::QPACK::StaticTable

  def test_entries
    assert_equal 99, StaticTable::ENTRIES.size
    assert_equal [":authority", ""], StaticTable.entry(0)
    assert_equal [":method", "GET"], StaticTable.entry(17)
    assert_equal [":status", "200"], StaticTable.entry(25)
    assert_equal ["accept", "*/*"], StaticTable.entry(29)
    assert_equal ["content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"], StaticTable.entry(85)
    assert_equal ["x-frame-options", "sameorigin"], StaticTable.entry(98)
    assert_nil StaticTable.entry(99)
    assert_nil StaticTable.entry(-1)
  end

  def test_find_by_name_and_value
    StaticTable::ENTRIES.each_with_index do |(name, value), index|
      assert_equal index, StaticTable.find(name, value)
    end
    assert_nil StaticTable.find(":method".b, "PATCH".b)
    assert_nil StaticTable.find("x-unknown".b, "".b)
  end

  def test_find_by_name
    assert_equal 1, StaticTable.find_name(":path".b)
    assert_equal 44, StaticTable.find_name("content-type".b)
    assert_nil StaticTable.find_name("x-unknown".b)
    StaticTable::ENTRIES.each do |name, _|
      assert_equal name, StaticTable.entry(StaticTable.find_name(name)).first
    end
  end

  def test_strings_are_frozen_binary_and_shareable
    StaticTable::ENTRIES.flatten.each do |string|
      assert_equal Encoding::BINARY, string.encoding
      assert string.frozen?
    end
    assert Ractor.shareable?(StaticTable::ENTRIES)
    assert Ractor.shareable?(StaticTable::INDEX)
    assert Ractor.shareable?(StaticTable::NAMES)
  end
end
