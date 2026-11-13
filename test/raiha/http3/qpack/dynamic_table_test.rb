require "test_helper"
require "raiha/http3/qpack"

# RFC 9204 "Dynamic Table", as the decoder keeps it.
class RaihaNextQPACKDynamicTableTest < Minitest::Test
  QPACK = Raiha::HTTP3::QPACK

  def test_starts_empty_with_no_capacity
    table = QPACK::DynamicTable.new(4096)
    assert_equal [0, 0, 0], [table.capacity, table.size, table.insert_count]
    assert_equal 128, table.max_entries
    assert_raises(QPACK::Malformed) { table.insert("a".b, "b".b) }
  end

  def test_entries_by_absolute_index
    table = table_of(220)
    table.insert("foo".b, "bar".b)
    table.insert(":authority".b, "www.example.com".b)
    assert_equal ["foo", "bar"], table.entry(0)
    assert_equal [":authority", "www.example.com"], table.entry(1)
    assert_nil table.entry(2)
    assert_equal [2, 38 + 57], [table.insert_count, table.size]
  end

  # RFC 9204 "Dynamic Table Capacity and Eviction": the oldest go first,
  # until the new entry fits.
  def test_inserting_evicts_the_oldest
    table = table_of(100)
    table.insert("a".b, "x" * 10) # 43
    table.insert("b".b, "x" * 10) # 43
    table.insert("c".b, "x" * 20) # 53: evicts "a"
    assert_nil table.entry(0)
    assert_equal ["b", "x" * 10], table.entry(1)
    assert_equal ["c", "x" * 20], table.entry(2)
    assert_equal 96, table.size
  end

  def test_an_entry_larger_than_the_capacity
    table = table_of(64)
    table.insert("a".b, "b".b)
    assert_raises(QPACK::Malformed) { table.insert("a".b, "x" * 32) } # 65
    assert_equal ["a", "b"], table.entry(0), "nothing is evicted for it"
    table.insert("a".b, "x" * 31) # 64, the whole table
    assert_nil table.entry(0)
  end

  def test_reducing_the_capacity_evicts
    table = table_of(200)
    3.times { |index| table.insert("n#{index}".b, "v".b) } # 35 each
    table.resize(70)
    assert_equal [nil, ["n1", "v"], ["n2", "v"]], (0..2).map { table.entry(_1) }
    table.resize(0)
    assert_equal 0, table.size
    assert_nil table.entry(2)
    table.resize(200)
    table.insert("n3".b, "v".b)
    assert_equal ["n3", "v"], table.entry(3)
  end

  def test_the_capacity_may_not_pass_the_maximum
    table = QPACK::DynamicTable.new(4096)
    table.resize(4096)
    assert_raises(QPACK::Malformed) { table.resize(4097) }
    assert_raises(QPACK::Malformed) { QPACK::DynamicTable.new(0).resize(1) }
  end

  # The ring doubles past its first slots and wraps around as entries go;
  # it agrees with a plain list of the entries throughout.
  def test_agrees_with_a_list_of_the_entries
    random = Random.new(9204)
    table = table_of(4096)
    list = []
    evicted = 0
    2_000.times do |step|
      if step % 500 == 499
        capacity = random.rand(0..4096)
        table.resize(capacity)
      else
        capacity = table.capacity
        name = random.bytes(random.rand(0..40))
        value = random.bytes(random.rand(0..60))
        next if name.bytesize + value.bytesize + 32 > capacity
        table.insert(name, value)
        list << [name, value]
      end
      size = list.drop(evicted).sum { |name, value| name.bytesize + value.bytesize + 32 }
      while size > capacity
        name, value = list[evicted]
        size -= name.bytesize + value.bytesize + 32
        evicted += 1
      end
      assert_equal size, table.size
      assert_equal list.size, table.insert_count
      assert_nil table.entry(evicted - 1) if evicted.positive?
      (evicted...list.size).each { |index| assert_equal list[index], table.entry(index) }
    end
  end

  private def table_of(capacity)
    QPACK::DynamicTable.new(capacity).tap { _1.resize(capacity) }
  end
end
