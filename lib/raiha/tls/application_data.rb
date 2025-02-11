module Raiha
  module TLS
    class ApplicationData
      attr_accessor :content

      def self.deserialize(buf)
        self.new.tap do |application_data|
          application_data.content = buf
        end
      end

      def serialize
        content
      end
    end
  end
end
