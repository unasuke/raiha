require "test_helper"
require "raiha/tls"
require "pp"

class RaihaTLSMaskedInspectTest < Minitest::Test
  class Secret < Data.define(:name, :key, :parts)
    include Raiha::TLS::MaskedInspect

    def masked_members = %i[key parts]
  end

  def setup
    @secret = Secret.new(name: "n", key: "\x01\x02\x03".b, parts: ["ab".b, "cde".b])
  end

  def test_inspect_shows_masked_members_by_size
    assert_equal '#<data RaihaTLSMaskedInspectTest::Secret name="n", key=[3 bytes], parts=[[2 bytes], [3 bytes]]>', @secret.inspect
  end

  def test_to_s_and_pp_are_masked_too
    assert_equal @secret.inspect, @secret.to_s
    assert_equal "#{@secret.inspect}\n", @secret.pretty_inspect
  end

  def test_equality_still_compares_every_member
    refute_equal @secret, @secret.with(key: "\x01\x02\x04".b)
    assert_equal @secret, Secret.new(name: "n", key: "\x01\x02\x03".b, parts: ["ab".b, "cde".b])
  end

  def test_mask_of_other_values
    assert_equal "[masked]", Raiha::TLS::MaskedInspect.mask(42)
  end
end
