require "test_helper"
require "fileutils"
require "support/qpack_offline_interop"
require "json"
require "open3"
require "tmpdir"

# The QPACK encoder on the QIF files of the qifs corpus: what it writes
# decodes back to them with the decoder of the next release of raiha and
# with ls-qpack, through pylsqpack, which uv resolves when the test runs.
# The encoder refers to no dynamic table, so both decoders allow none.
# `rake test:qifs` fetches the corpus into tmp/qifs.
class NextQPACKQifsEncodingTest < Minitest::Test
  include NextQPACKOfflineInterop

  PYTHON = %w[uv run --with pylsqpack python3].freeze
  DECODE = File.expand_path("../../support/pylsqpack_decode.py", __dir__)
  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }

  def setup
    skip "the qifs corpus is not in #{QIFS_DIR}; run rake test:qifs" unless Dir.exist?(File.join(QIFS_DIR, "qifs"))
    @qifs = Dir[File.join(QIFS_DIR, "qifs", "*.qif")].sort
    refute_empty @qifs
  end

  def test_decodes_back_with_the_decoder
    @qifs.each do |path|
      lists = qif(path)
      decoded = decode_file(encode_file(lists), table: 0, blocked: 0)
      assert_kind_of Hash, decoded, "#{path}: #{decoded.inspect}"
      assert_equal lists, decoded.sort.map(&:last), path
    end
  end

  def test_decodes_back_with_ls_qpack
    skip "uv not found" unless system("uv", "--version", out: File::NULL, err: File::NULL)
    Dir.mktmpdir("next-qifs-", TMP) do |dir|
      @qifs.each do |path|
        lists = qif(path)
        encoded = File.join(dir, "#{File.basename(path, ".qif")}.out.0.0.1")
        File.binwrite(encoded, encode_file(lists))
        stdout, stderr, status = Open3.capture3(*PYTHON, DECODE, encoded, "0", "0")
        assert status.success?, "#{path}: #{stderr}"
        decoded = JSON.parse(stdout)
        refute decoded.key?("error"), "#{path}: ls-qpack refused it: #{decoded["error"]}"
        actual = decoded.sort_by { |stream_id, _| Integer(stream_id) }.map do |_, fields|
          fields.map { |name, value| QPACK::Field.new(name: [name].pack("H*"), value: [value].pack("H*")) }
        end
        assert_equal lists, actual, path
      end
    end
  end
end
