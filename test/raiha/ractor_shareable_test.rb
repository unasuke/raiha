require "test_helper"
require "raiha"

# The workers of a server each run in a Ractor of their own, where a
# constant that is not shareable cannot be read: every constant under
# Raiha must be shareable, so that nothing the workers reach fails with
# Ractor::IsolationError.
class RaihaRactorShareableTest < Minitest::Test
  # Module#name, called as the class's own, which a module that defines a
  # `name` of its own does not change.
  NAME = Module.instance_method(:name)

  # "Module::CONSTANT" of each constant under `root` whose value is not
  # shareable; modules are walked rather than judged.
  def unshareable(root)
    found = []
    seen = {}.compare_by_identity
    walk = lambda do |mod|
      next if seen[mod]
      seen[mod] = true
      mod.constants(false).each do |name|
        value = mod.const_get(name, false)
        if value.is_a?(Module)
          walk.call(value) if NAME.bind_call(value)&.start_with?("Raiha")
        elsif !Ractor.shareable?(value)
          found << "#{NAME.bind_call(mod)}::#{name}"
        end
      end
    end
    walk.call(root)
    found
  end

  def test_every_constant_under_the_next_release_is_shareable
    assert_empty unshareable(Raiha)
  end

  # Guards against the walk silently reaching nothing.
  def test_the_walk_finds_a_constant_that_is_not_shareable
    mod = Module.new
    Raiha.const_set(:RactorShareableTestProbe, mod)
    mod.const_set(:LIST, [+"not frozen"])
    assert_equal ["Raiha::RactorShareableTestProbe::LIST"], unshareable(Raiha)
  ensure
    Raiha.send(:remove_const, :RactorShareableTestProbe) if Raiha.const_defined?(:RactorShareableTestProbe, false)
  end
end
