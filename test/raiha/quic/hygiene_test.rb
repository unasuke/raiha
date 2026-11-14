require "test_helper"
require "prism"

# The QUIC layer reaches into the TLS layer's handshake at two places only:
# the TLS binding alone drives the Machine and reads its Outputs and Events,
# and the Endpoint alone holds an Acceptor, so that a reader can trust
# what each of the two does with them.
class RaihaQUICHygieneTest < Minitest::Test
  QUIC_DIR = File.expand_path("../../../lib/raiha/quic", __dir__)

  PLACES = {
    "TLS::Handshake::Machine, TLS::Output and TLS::Event" => [/(?:\A|::)TLS::(?:Handshake::Machine|Output|Event)(?:::|\z)/, "tls_binding.rb"],
    "TLS::Handshake::Acceptor" => [/(?:\A|::)TLS::Handshake::Acceptor(?:::|\z)/, "endpoint.rb"]
  }.freeze

  # The constant paths named in each file under lib/raiha/quic.
  def constants
    @constants ||= Dir.glob("**/*.rb", base: QUIC_DIR).sort.to_h do |file|
      names = []
      walk = lambda do |node|
        names << node.slice if node.is_a?(Prism::ConstantPathNode)
        node.compact_child_nodes.each(&walk)
      end
      walk.(Prism.parse_file(File.join(QUIC_DIR, file)).value)
      [file, names]
    end
  end

  def test_each_is_named_at_its_place_alone
    PLACES.each do |what, (pattern, place)|
      named = constants.select { |_, names| names.any? { _1.match?(pattern) } }.keys
      assert_equal [place], named, what
    end
  end
end
