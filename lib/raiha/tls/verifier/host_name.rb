# frozen_string_literal: true

require "ipaddr"

module Raiha::Next::TLS
  module Verifier
    # Whether a certificate is valid for a name, by RFC 9525.
    #
    # Only subjectAltName counts: a DNS name against the dNSName entries, an
    # IP address octet for octet against the iPAddress entries. There is no
    # fallback to the subject's commonName, which RFC 9525 ended. A wildcard
    # is valid only as the whole leftmost label, and then matches exactly
    # one label; a presented name with a "*" anywhere else is ignored.
    module HostName
      SUBJECT_ALT_NAME = "subjectAltName"
      DNS_NAME = 2
      IP_ADDRESS = 7

      # `name` is in the normal form a handshake uses: ASCII lowercase with
      # no trailing dot, or an IP address literal.
      def self.match?(certificate, name)
        dns_names, ip_addresses = subject_alt_names(certificate)
        if (address = ip_address(name))
          ip_addresses.include?(address.hton)
        else
          dns_names.any? { |presented| dns_name_match?(presented, name) }
        end
      end

      # IPv6 may come in brackets, as in a URI.
      def self.ip_address(name)
        literal = name.delete_prefix("[").delete_suffix("]")
        return nil unless literal.match?(/\A[0-9.]+\z/) || literal.include?(":")
        IPAddr.new(literal)
      rescue IPAddr::Error
        nil
      end

      def self.dns_name_match?(presented, name)
        presented = presented.downcase.delete_suffix(".")
        return presented == name unless presented.include?("*")
        return false unless presented.start_with?("*.") && presented.count("*") == 1
        suffix = presented.delete_prefix("*")
        first_label, rest = name.split(".", 2)
        !first_label.nil? && !first_label.empty? && !rest.nil? && ".#{rest}" == suffix
      end

      # The dNSName and iPAddress entries of the subjectAltName extension;
      # none when the extension is absent or malformed.
      def self.subject_alt_names(certificate)
        # @type var dns_names: Array[String]
        dns_names = []
        # @type var ip_addresses: Array[String]
        ip_addresses = []
        extension = certificate.extensions.find { |ext| ext.oid == SUBJECT_ALT_NAME }
        return [dns_names, ip_addresses] unless extension
        general_names = OpenSSL::ASN1.decode(extension.value_der).value
        return [dns_names, ip_addresses] unless general_names.is_a?(Array)
        general_names.each do |general_name|
          next unless general_name.tag_class == :CONTEXT_SPECIFIC
          value = general_name.value
          value = value.first.value if value.is_a?(Array)
          next unless value.is_a?(String)
          case general_name.tag
          when DNS_NAME then dns_names << value
          when IP_ADDRESS then ip_addresses << value.b
          end
        end
        [dns_names, ip_addresses]
      rescue OpenSSL::ASN1::ASN1Error
        [[], []]
      end
    end
  end
end
