# frozen_string_literal: true

require "openssl"

# Utility module for cryptography
module Raiha::CryptoUtil
  # Provide HKDF-Expand-Label function
  #
  #   HKDF-Expand-Label(Secret, Label, Context, Length) =
  #     HKDF-Expand(Secret, HkdfLabel, Length)
  #
  #    Where HkdfLabel is specified as:
  #
  #    struct {
  #        uint16 length = Length;
  #        opaque label<7..255> = "tls13 " + Label;
  #        opaque context<0..255> = Context;
  #    } HkdfLabel;
  # from RFC 8446
  #
  # @see https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
  # @see https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3
  # @see OpenSSL::KDF.hkdf
  #
  # @param secret [String] (In RFC5869, this is _PRK_) a pseudorandom key of at least HashLen octets
  #   (usually, the output from the extract step)
  # @param label [String] An element of _Hkdflabel_ (part of _info_ in RFC 5869)
  # @param context [String] An element of _HkdfLabel_ (part of _info_ in RFC 5869)
  # @param length [Integer] length of output keying material in octets (<= 255*HashLen)
  # @return [String] output keying material with label
  def hkdf_expand_label(secret, label, context, length)
    info = [length].pack("n")
    info += "tls13 #{label}".length.chr + "tls13 #{label}"
    info += context.length.chr + context
    hkdf_expand(secret, info, length)
  end
  module_function :hkdf_expand_label

  # Provide HKDF-Expand function
  #
  #   HKDF-Expand(PRK, info, L) -> OKM
  # from RFC 5869
  #
  # @see https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3
  # @see OpenSSL::KDF.hkdf
  #
  # @param prk [String] a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
  # @param info [String] optional context and application specific information (can be a zero-length string)
  # @param length [Integer] length of output keying material in octets (<= 255*HashLen)
  # @return [String] output keying material (of "length" octets)
  def hkdf_expand(prk, info, length)
    hash_length = OpenSSL::Digest.new("SHA256").digest_length
    n = (length.to_f / hash_length).ceil
    okm = ""
    t = ""
    (1..n).each do |i|
      t = OpenSSL::HMAC.digest("SHA256", prk, t + info + i.chr)
      okm += t
    end
    pp okm.unpack1("H*")
    okm[0...length]
  end
  module_function :hkdf_expand
end
