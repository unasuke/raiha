require "test_helper"
require "raiha/quic/wire/retry"

class RaihaQuicWireRetryTest < Minitest::Test
  # RFC 9001 Appendix A.4 — Retry packet sample. The full packet (with the
  # trailing 16-byte Integrity Tag) is:
  #
  #   ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
  #   0f2496ba
  #
  # This packet is the server's Retry for a connection where the client's
  # original destination connection ID was:
  #
  #   ODCID = 0x8394c8f03e515708
  ODCID = ["8394c8f03e515708"].pack("H*").freeze
  SAMPLE = [
    "ff000000010008f067a5502a4262b574" +
    "6f6b656e04a265ba2eff4d829058fb3f" +
    "0f2496ba"
  ].pack("H*").freeze

  def test_verify_integrity_tag_accepts_rfc_sample
    assert Raiha::Quic::Wire::Retry.verify_integrity_tag(
      data: SAMPLE,
      original_destination_connection_id: ODCID
    )
  end

  def test_verify_integrity_tag_rejects_mismatched_odcid
    tampered_odcid = "\x00".b * 8
    refute Raiha::Quic::Wire::Retry.verify_integrity_tag(
      data: SAMPLE,
      original_destination_connection_id: tampered_odcid
    )
  end

  def test_verify_integrity_tag_rejects_tampered_body
    corrupted = SAMPLE.dup
    corrupted.setbyte(1, corrupted.getbyte(1) ^ 0xff)

    refute Raiha::Quic::Wire::Retry.verify_integrity_tag(
      data: corrupted,
      original_destination_connection_id: ODCID
    )
  end

  def test_compute_integrity_tag_matches_sample
    body = SAMPLE.byteslice(0, SAMPLE.bytesize - 16)
    expected_tag = SAMPLE.byteslice(-16, 16)

    computed = Raiha::Quic::Wire::Retry.compute_integrity_tag(
      original_destination_connection_id: ODCID,
      retry_packet_without_tag: body
    )
    assert_equal expected_tag, computed
  end
end
