# frozen_string_literal: true

require_relative "../crypto_util"
require "openssl"

module Raiha
  module TLS
    # KeySchedule
    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
    class KeySchedule
      attr_accessor :public_key
      attr_accessor :pkey
      attr_accessor :group
      attr_reader :shared_secret

      def initialize(mode:)
        @mode = mode
        @shared_secret = nil
      end

      def compute_shared_secret
        raise unless @group

        @shared_secret = case @group
        when "prime256v1", "secp384r1", "secp521r1"
          group = OpenSSL::PKey::EC::Group.new(@group)
          @pkey.dh_compute_key(OpenSSL::PKey::EC::Point.new(group, @public_key))
        when "x25519"
          @pkey.derive(OpenSSL::PKey.new_raw_public_key("x25519", @public_key))
        else
          raise "TODO: #{@group} is not supported (yet)"
        end
      end

      def derive_secret()
      end
    end
  end
end
