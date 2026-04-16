require "test_helper"
require "raiha/http3/qpack/static_table"

class RaihaHTTP3QPACKStaticTableTest < Minitest::Test
  def test_size_matches_rfc_9204_appendix_a
    # RFC 9204 Appendix A defines 99 entries (indices 0-98)
    assert_equal 99, Raiha::HTTP3::QPACK::StaticTable.size
  end

  def test_entry_by_index
    assert_equal [":authority", ""], Raiha::HTTP3::QPACK::StaticTable[0]
    assert_equal [":method", "GET"], Raiha::HTTP3::QPACK::StaticTable[17]
    assert_equal [":status", "200"], Raiha::HTTP3::QPACK::StaticTable[25]
    assert_equal ["x-frame-options", "sameorigin"], Raiha::HTTP3::QPACK::StaticTable[98]
  end

  def test_find_exact_match
    assert_equal 17, Raiha::HTTP3::QPACK::StaticTable.find(":method", "GET")
    assert_equal 23, Raiha::HTTP3::QPACK::StaticTable.find(":scheme", "https")
    assert_equal 25, Raiha::HTTP3::QPACK::StaticTable.find(":status", "200")
  end

  def test_find_returns_nil_for_no_match
    assert_nil Raiha::HTTP3::QPACK::StaticTable.find(":method", "TRACE")
    assert_nil Raiha::HTTP3::QPACK::StaticTable.find("x-custom-header", "value")
  end

  def test_find_name_returns_first_matching
    # :method has multiple entries, find_name returns the first
    assert_equal 15, Raiha::HTTP3::QPACK::StaticTable.find_name(":method")
    # :path has a single entry
    assert_equal 1, Raiha::HTTP3::QPACK::StaticTable.find_name(":path")
  end

  def test_find_name_returns_nil_for_unknown_name
    assert_nil Raiha::HTTP3::QPACK::StaticTable.find_name("x-unknown")
  end
end
