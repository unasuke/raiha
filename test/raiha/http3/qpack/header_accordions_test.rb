require "test_helper"
require "raiha/http3/qpack"

# Header Accordions (FoxIO, 2026): field sections that make a decoder
# expand a few bytes on the wire into far more memory. The decoder stops
# at the budget, 64 KiB by default, and expands no more than that.
class RaihaQPACKHeaderAccordionsTest < Minitest::Test
  QPACK = Raiha::HTTP3::QPACK
  MIB = 1 << 20

  # About 150,000 fields of unique names in 1 MiB, each 7 octets on the
  # wire and 37 against the budget.
  def test_unique_names_packed_into_a_section
    section = "\x00\x00".b + (0...(MIB / 7)).map { |index| [0x25].pack("C") + format("%05d", index % 100_000) + "\x00" }.join.b
    assert_operator section.bytesize, :>, MIB - 7
    result, allocated = allocations { QPACK::Decoder.new.decode(0, section) }
    assert_kind_of QPACK::Oversized, result
    assert_operator allocated, :<, 20_000, "the decoder stopped near 1,800 fields instead of expanding 150,000"
  end

  # An entry of about 4 KiB referred to again and again by a byte each:
  # 4,064 octets against the budget for each byte on the wire.
  def test_one_large_entry_referred_to_by_every_byte
    decoder = QPACK::Decoder.new(max_table_capacity: 4096)
    decoder.receive_encoder_stream(QPACK::Writer.new.integer(4096, 5, 0x20).string("a".b, 6, 0x40).string("x".b * 4031, 8).to_s)
    section = "\x02\x00".b + ("\x80".b * MIB)
    result, allocated = allocations { decoder.decode(4, section) }
    assert_kind_of QPACK::Oversized, result
    assert_operator allocated, :<, 1_000, "the decoder stopped after 17 references"
    assert_equal "\x44\x01".b, decoder.take_instructions, "the stream is cancelled"
  end

  private def allocations
    before = GC.stat(:total_allocated_objects)
    result = yield
    [result, GC.stat(:total_allocated_objects) - before]
  end
end
