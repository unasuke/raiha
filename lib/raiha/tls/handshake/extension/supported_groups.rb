require_relative "abstract_extension"
require "stringio"

module Raiha
  module TLS
    class Handshake
      class Extension
        # Supported Groups Extension
        #
        #  enum {
        #
        #      /* Elliptic Curve Groups (ECDHE) */
        #      secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
        #      x25519(0x001D), x448(0x001E),
        #
        #      /* Finite Field Groups (DHE) */
        #      ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
        #      ffdhe6144(0x0103), ffdhe8192(0x0104),
        #
        #      /* Reserved Code Points */
        #      ffdhe_private_use(0x01FC..0x01FF),
        #      ecdhe_private_use(0xFE00..0xFEFF),
        #      (0xFFFF)
        #  } NamedGroup;
        #
        #  struct {
        #      NamedGroup named_group_list<2..2^16-1>;
        #  } NamedGroupList;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
        # @see https://datatracker.ietf.org/doc/rfc7919/
        class SupportedGroups < AbstractExtension
          EXTENSION_TYPE_NUMBER = 10
          NAMED_GROUPS = { # TODO: Move to somewhere (define on specific class)
            "prime256v1" => "\x00\x17", # secp256r1
            "secp384r1" => "\x00\x18",
            "secp521r1" => "\x00\x19",
            "x25519" => "\x00\x1D",
            "x448" => "\x00\x1E",
            "ffdhe2048" => "\x01\x00",
            "ffdhe3072" => "\x01\x01",
            "ffdhe4096" => "\x01\x02",
            "ffdhe6144" => "\x01\x03",
            "ffdhe8192" => "\x01\x04",
          }.freeze

          FFDHE_PRIVATE_USE = (0x01FC..0x01FF)
          ECDHE_PRIVATE_USE = (0xFE00..0xFEFF)

          attr_accessor :groups

          def extension_data=(data)
            super
            @groups = []

            buf = StringIO.new(data)
            group_count = buf.read(2).unpack1("n") / 2
            group_count.times do
              value = buf.read(2)
              group = NAMED_GROUPS.key(value)
              if group
                @groups << group
              else
                @groups << "ffdhe_private_use" if FFDHE_PRIVATE_USE.include?(value.unpack1("n"))
                @groups << "ecdhe_private_use" if ECDHE_PRIVATE_USE.include?(value.unpack1("n"))
              end
            end
          end

          def serialize
            data = [@groups.length * 2].pack("n") + @groups.map { |group| NAMED_GROUPS[group] }.join
            [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
          end
        end
      end
    end
  end
end
