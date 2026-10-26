# frozen_string_literal: true

require "strscan"

module Raiha::Next::HTTP3
  # Reads a Dictionary of Structured Field Values (RFC 8941), the form of
  # the Priority header field and of PRIORITY_UPDATE (RFC 9218 "Priority
  # Parameters"). Every type of item is read, so that a field is known to
  # be a Dictionary or not, but only its members' values come back:
  # Integers, Floats for Decimals, Strings for Strings and Byte Sequences,
  # Symbols for Tokens, true and false, and Arrays for Inner Lists. The
  # parameters of members are read and dropped.
  module StructuredField
    KEY = /[a-z*][a-z0-9_\-.*]*/
    TOKEN = %r{[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*}
    INTEGER = /-?[0-9]{1,15}(?![0-9.])/
    DECIMAL = /-?[0-9]{1,12}\.[0-9]{1,3}(?![0-9.])/
    BYTE_SEQUENCE = %r{:([A-Za-z0-9+/]*={0,2}):}
    STRING_RUN = /[\x20\x21\x23-\x5b\x5d-\x7e]+/n
    OWS = /[ \t]*/
    SP = / */

    # The members of the Dictionary `text` is, by key, the last of a key
    # that repeats; nil when it is not one.
    def self.dictionary(text)
      scanner = StringScanner.new(text.b)
      scanner.skip(SP)
      members = {} #: Hash[String, value]
      until scanner.eos?
        key = scanner.scan(KEY) or return nil
        if scanner.skip("=")
          value = member_value(scanner)
          return nil if value.nil?
        else
          value = true
          parameters(scanner) or return nil
        end
        members[key] = value
        scanner.skip(OWS)
        break if scanner.eos?
        return nil unless scanner.skip(",")
        scanner.skip(OWS)
        return nil if scanner.eos?
      end
      members
    end

    # An Item or an Inner List, with its parameters; nil when there is
    # neither.
    def self.member_value(scanner)
      value = scanner.match?("(") ? inner_list(scanner) : bare_item(scanner)
      return nil if value.nil?
      parameters(scanner) or return nil
      value
    end

    def self.inner_list(scanner)
      scanner.skip("(")
      items = [] #: Array[value]
      loop do
        scanner.skip(SP)
        return items if scanner.skip(")")
        item = bare_item(scanner)
        return nil if item.nil?
        parameters(scanner) or return nil
        items << item
        return nil unless scanner.match?(/[ )]/)
      end
    end

    # Each parameter after a ";"; false when one does not parse.
    def self.parameters(scanner)
      while scanner.skip(";")
        scanner.skip(SP)
        scanner.skip(KEY) or return false
        return false if scanner.skip("=") && bare_item(scanner).nil?
      end
      true
    end

    def self.bare_item(scanner)
      if (decimal = scanner.scan(DECIMAL)) then Float(decimal)
      elsif (integer = scanner.scan(INTEGER)) then Integer(integer, 10)
      elsif scanner.match?('"') then string(scanner)
      elsif scanner.scan(BYTE_SEQUENCE) then scanner[1].unpack1("m") # steep:ignore
      elsif scanner.skip("?1") then true
      elsif scanner.skip("?0") then false
      elsif (token = scanner.scan(TOKEN)) then token.to_sym
      end
    end

    def self.string(scanner)
      scanner.skip('"')
      string = +""
      loop do
        if scanner.skip('"') then return string
        elsif scanner.skip("\\")
          escaped = scanner.scan(/["\\]/) or return nil
          string << escaped
        elsif (run = scanner.scan(STRING_RUN)) then string << run
        else return nil
        end
      end
    end

    private_class_method :member_value, :inner_list, :parameters, :bare_item, :string
  end
end
