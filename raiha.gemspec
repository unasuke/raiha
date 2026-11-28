lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "raiha/version"

Gem::Specification.new do |spec|
  spec.name          = "raiha"
  spec.version       = Raiha::VERSION
  spec.authors       = ["Yusuke Nakamura"]
  spec.email         = ["yusuke1994525@gmail.com"]
  spec.required_ruby_version = '>= 4.0'

  spec.summary       = "QUIC, HTTP/3 and TLS 1.3 written in Ruby"
  spec.description   = "QUIC, HTTP/3 with QPACK, and TLS 1.3 implemented in Ruby itself, " \
    "with the openssl gem providing only the cryptographic primitives. " \
    "A sans-I/O core, and a runtime over UDP sockets under a Fiber scheduler or on threads."
  spec.homepage      = "https://github.com/unasuke/raiha"
  spec.license       = "Apache-2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z -- lib sig docs examples README.md CHANGELOG.md LICENSE`.split("\x0")
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "openssl", ">= 4.0"
end
