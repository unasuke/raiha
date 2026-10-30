require "raiha/next/test_helper"
require "prism"

# Each kind of change in the state machine has exactly one place, so that a
# reader can trust it and a new code path cannot slip past it. These tests
# find every place that makes the change and compare with the one allowed.
class RaihaNextTLSHandshakeHygieneTest < Minitest::Test
  TLS_DIR = File.expand_path("../../../../../lib/raiha/next/tls", __dir__)

  # Where something happens: [file under lib/raiha/next/tls, enclosing method].
  class Finder < Prism::Visitor
    attr_reader :found

    def initialize(file, &matcher)
      super()
      @file = file
      @matcher = matcher
      @methods = []
      @found = []
    end

    def visit_def_node(node)
      @methods.push(node.name)
      super
    ensure
      @methods.pop
    end

    %i[visit_instance_variable_write_node visit_instance_variable_or_write_node visit_call_node].each do |visit|
      define_method(visit) do |node|
        @found << [@file, @methods.last] if @matcher.call(node)
        super(node)
      end
    end
  end

  def sites(&matcher)
    Dir.glob("**/*.rb", base: TLS_DIR).sort.flat_map do |file|
      finder = Finder.new(file, &matcher)
      Prism.parse_file(File.join(TLS_DIR, file)).value.accept(finder)
      finder.found
    end.uniq
  end

  def ivar_write?(node, name)
    (node.is_a?(Prism::InstanceVariableWriteNode) || node.is_a?(Prism::InstanceVariableOrWriteNode)) && node.name == name
  end

  def new_of?(node, constant)
    node.is_a?(Prism::CallNode) && node.name == :new && node.receiver&.slice&.end_with?(constant)
  end

  def call_on?(node, receiver, names)
    node.is_a?(Prism::CallNode) && names.include?(node.name) && node.receiver&.slice == receiver
  end

  CONDUCTOR = "handshake/conductor.rb"

  # The state is assigned only by the transition method, besides its
  # starting value.
  def test_state_is_assigned_in_one_place
    assert_equal [[CONDUCTOR, :initialize], [CONDUCTOR, :transition!]], sites { |node| ivar_write?(node, :@state) }
  end

  def test_epochs_move_in_one_place
    %i[@read_epoch @write_epoch].each do |name|
      assert_equal [[CONDUCTOR, :initialize], [CONDUCTOR, :change_epochs!]], sites { |node| ivar_write?(node, name) }, name
    end
  end

  # The Acceptor has a fail! of its own: it runs before any Machine exists.
  # An alert from the peer (TCP::Event::PeerAlert) is not one of ours.
  def test_alerts_are_built_in_one_place
    assert_equal [["handshake/acceptor.rb", :fail!], [CONDUCTOR, :fail!]],
      sites { |node| new_of?(node, "::Alert") || (new_of?(node, "Alert") && node.receiver&.slice == "Alert") }
  end

  # The transcript is added to when receiving or sending a message, around a
  # ServerHello or HelloRetryRequest, and in two parts around the binders of
  # a ClientHello, and nowhere else.
  def test_transcript_changes_in_the_conductor_only
    found = sites { |node| call_on?(node, "@transcript", %i[<< select! restart_with_message_hash!]) }
    assert_equal [
      [CONDUCTOR, :emit_client_hello_with_binders!],
      [CONDUCTOR, :emit_hello_retry_request!], [CONDUCTOR, :emit_message!], [CONDUCTOR, :emit_server_hello!],
      [CONDUCTOR, :process], [CONDUCTOR, :receive_hello_retry_request!], [CONDUCTOR, :record_client_hello],
      [CONDUCTOR, :record_server_hello!]
    ], found.sort
  end

  # A test oracle reads these to know a check passed, so they are built
  # only right where it passes.
  def test_verified_traces_are_built_where_the_checks_pass
    authentication = "handshake/authentication_messages.rb"
    {
      "PeerCertificateVerified" => [[authentication, :verify_certificate]],
      "PeerSignatureVerified" => [[authentication, :verify_certificate_verify]],
      "PeerFinishedVerified" => [[authentication, :verify_finished]],
      "BinderVerified" => [["handshake/server_side.rb", :verify_binder]]
    }.each do |name, expected|
      assert_equal expected, sites { |node| new_of?(node, name) }, name
    end
  end
end
