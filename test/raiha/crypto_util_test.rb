# frozen_string_literal: true

require "test_helper"
require "raiha/crypto_util"

class RaihaCryptoUtilTest < Minitest::Test
  def test_hkdf_expand_label
    # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-a.1
    initial_secret = ["7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"].pack("H*")

    client_initial_secret = Raiha::CryptoUtil.hkdf_expand_label(initial_secret, "client in", "", 32)
    assert_equal ["c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"].pack("H*"), client_initial_secret

    key = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic key", "", 16)
    assert_equal ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*"), key

    iv = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic iv", "", 12)
    assert_equal ["fa044b2f42a3fd3b46fb255c"].pack("H*"), iv

    hp = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic hp", "", 16)
    assert_equal ["9f50449e04a0e810283a1e9933adedd2"].pack("H*"), hp
  end
end
