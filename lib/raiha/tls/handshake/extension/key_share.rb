require_relative "abstract_extension"
require "openssl"

module Raiha
  module TLS
    class Handshake
      class Extension
        # Key Share Extension
        #
        #   struct {
        #       NamedGroup group;
        #       opaque key_exchange<1..2^16-1>;
        #   } KeyShareEntry;
        #
        #   struct {
        #       KeyShareEntry client_shares<0..2^16-1>;
        #   } KeyShareClientHello;
        #
        #   struct {
        #       NamedGroup selected_group;
        #   } KeyShareHelloRetryRequest;
        #
        #   struct {
        #       KeyShareEntry server_share;
        #   } KeyShareServerHello;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
        class KeyShare < AbstractExtension
          EXTENSION_TYPE_NUMBER = 51

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

          attr_accessor :private_key
          attr_accessor :ec
          attr_accessor :groups
          attr_accessor :key_exchange

          def self.generate_key(groups = ["prime256v1"], on: :client_hello)
            self.new(on: on).tap do |key_share|
              key_share.groups = []
              groups.each do |group|
                ec = OpenSSL::PKey::EC.generate(group) # TODO: x25519
                key_share.groups << { group: group, key_exchange: ec.public_key.to_octet_string(:uncompressed) }
              end
            end
          end

          def extension_data=(data)
            super
            buf = StringIO.new(data)
            @groups = []
            case @on
            when :client_hello
              client_shares_length = buf.read(2).unpack1("n")
              read_client_shares_length = 0
              loop do
                group_name = NAMED_GROUPS.key(buf.read(2))
                read_client_shares_length += 2
                key_exchange_length = buf.read(2).unpack1("n")
                read_client_shares_length += 2
                key_exchange = buf.read(key_exchange_length)
                read_client_shares_length += key_exchange_length
                @groups << validate_group_and_key_exchange(group_name, key_exchange)

                if client_shares_length == read_client_shares_length
                  raise "TODO: mismatch length" unless buf.eof?

                  break
                end
              end
            when :server_hello
              group_name = NAMED_GROUPS.key(buf.read(2))
              key_exchange_length = buf.read(2).unpack1("n")
              key_exchange = buf.read(key_exchange_length)
              @groups << validate_group_and_key_exchange(group_name, key_exchange)
            else
              # TODO
            end
          end

          def serialize
            case @on
            when :client_hello
              serialize_for_client_hello
            when :server_hello
              serialize_for_server_hello
            when :hello_retry_request
              serialize_for_hello_retry_request
            else
              # TODO: raise?
            end
          end

          private def serialize_for_client_hello
            key_share_entries = @groups.map do |group|
              NAMED_GROUPS[group[:group]] + [group[:key_exchange].bytesize].pack("n") + group[:key_exchange]
            end.join

            key_share_data = [key_share_entries.bytesize].pack("n") + key_share_entries

            [EXTENSION_TYPE_NUMBER].pack("n") + [key_share_data.bytesize].pack("n") + key_share_data
          end

          private def serialize_for_server_hello
            raise "on server_hello, only one group is supported" unless @groups.size == 1

            key_share_data = NAMED_GROUPS[@groups.first[:group]] + [@groups.first[:key_exchange].bytesize].pack("n") + @groups.first[:key_exchange]

            [EXTENSION_TYPE_NUMBER].pack("n") + [key_share_data.bytesize].pack("n") + key_share_data
          end

          private def serialize_for_hello_retry_request
            raise NotImplementedError
          end

          private def validate_group_and_key_exchange(group_name, key_exchange)
            case group_name
            when "x25519"
              pkey = OpenSSL::PKey.new_raw_public_key(group_name, key_exchange) # verify given key_exchange is valid
              { group: group_name, key_exchange: pkey.raw_public_key }
            when "x448"
              # TODO: I need test vector...
              raise "x448"
            when "prime256v1", "secp384r1", "secp521r1"
              group = OpenSSL::PKey::EC::Group.new(group_name)
              point = OpenSSL::PKey::EC::Point.new(group, key_exchange) # verify given key_exchange is valid
              { group: group_name, key_exchange: point.to_octet_string(:uncompressed) }
            else
              # TODO:
              raise NotImplementedError
            end
          end
        end
      end
    end
  end
end
