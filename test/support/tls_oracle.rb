require "raiha/tls"

# The security oracle of the next release's TLS tests: what must hold once
# a handshake completes, whatever was fed to it. Bugs in this layer rarely
# raise; they complete without a check, so passing without an exception
# proves little. The Machine reports each check that passed as a Trace value
# built only where the check passes, and this reads those.
#
#   oracle = NextTLSOracle.new
#   client = Machine.client(..., tracer: oracle.client)
#   server = Machine.server(..., tracer: oracle.server)
#   ... run ...
#   assert_empty oracle.violations(client:, server:)
class NextTLSOracle
  TLS = Raiha::TLS
  Trace = TLS::Trace

  # A tracer that keeps every value.
  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value

    def of(kind) = @values.grep(kind)
  end

  attr_reader :client, :server

  def initialize
    @client = Recorder.new
    @server = Recorder.new
  end

  # What was violated, as messages; empty when everything holds. A side that
  # did not complete promises nothing. `client_auth` is the server's
  # Config#client_auth.
  def violations(client:, server:, client_auth: :none)
    found = []
    client_done = client.each_event.grep(TLS::Event::HandshakeComplete).first if client.complete?
    server_done = server.each_event.grep(TLS::Event::HandshakeComplete).first if server.complete?

    if client_done
      # The client authenticated the server: by its certificate and
      # signature, or by a PSK.
      certificate = @client.of(Trace::PeerCertificateVerified).any? { |t| t.purpose == :server }
      signature = !@client.of(Trace::PeerSignatureVerified).empty?
      unless (certificate && signature) || client_done.resumed
        found << "the client completed without verifying the server's certificate and signature"
      end
      found << "the client completed without verifying the server's Finished" if @client.of(Trace::PeerFinishedVerified).empty?
    end

    if server_done
      found << "the server resumed without verifying a binder" if server_done.resumed && @server.of(Trace::BinderVerified).empty?
      unless server_done.peer_certificates.empty?
        certificate = @server.of(Trace::PeerCertificateVerified).any? { |t| t.purpose == :client }
        signature = !@server.of(Trace::PeerSignatureVerified).empty?
        found << "the server accepted a client certificate without verifying it and its signature" unless certificate && signature
      end
      if client_auth == :required && server_done.peer_certificates.empty?
        found << "the server required a client certificate and completed without one"
      end
      found << "the server completed without verifying the client's Finished" if @server.of(Trace::PeerFinishedVerified).empty?
    end

    if client_done && server_done
      client_digest = @client.of(Trace::TranscriptUpdated).last&.digest
      server_digest = @server.of(Trace::TranscriptUpdated).last&.digest
      found << "the two sides completed with different transcripts" unless client_digest && client_digest == server_digest
    end
    found
  end
end
