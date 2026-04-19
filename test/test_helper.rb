if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
    enable_coverage :branch
  end
end

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "raiha"
require "debug"

require "support/custom_assertion"
require "minitest/autorun"
