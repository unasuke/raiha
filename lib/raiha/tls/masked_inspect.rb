# frozen_string_literal: true

module Raiha::TLS
  # Shows the members named by `#masked_members` only by size in `inspect`,
  # `to_s` and `pp`, so secrets stay out of logs. `==` and `to_h` still see
  # every member.
  #
  # `Data#inspect` does not consult `instance_variables_to_inspect`, so this
  # replaces it.
  module MaskedInspect
    def inspect
      fields = to_h.map do |name, value|
        shown = masked_members.include?(name) ? MaskedInspect.mask(value) : value.inspect
        "#{name}=#{shown}"
      end
      "#<data #{self.class.name} #{fields.join(", ")}>"
    end

    def to_s = inspect

    def pretty_print(q) = q.text(inspect)

    def self.mask(value)
      if value.is_a?(String)
        "[#{value.bytesize} bytes]"
      elsif value.is_a?(Array)
        "[#{value.map { |v| mask(v) }.join(", ")}]"
      else
        "[masked]"
      end
    end
  end
end
