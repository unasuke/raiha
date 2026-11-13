require "test_helper"
require "support/qpack_offline_interop"

# The QPACK decoder against the qifs corpus: what other implementations'
# encoders made of the QIF files decodes back to them. The encodings are
# those of qpack-05, the corpus's latest; qpack-02 and qpack-03 are of
# drafts older than RFC 9204's wire format. `rake test:qifs` fetches
# the corpus into tmp/qifs.
class NextQPACKQifsTest < Minitest::Test
  include NextQPACKOfflineInterop

  ENCODED = File.join(QIFS_DIR, "encoded", "qpack-05")
  IMPLEMENTATIONS = %w[f5 ls-qpack nghttp3 proxygen qthingey quinn].freeze

  def setup
    skip "the qifs corpus is not in #{QIFS_DIR}; run rake test:qifs" unless Dir.exist?(ENCODED)
  end

  # File names are <QIF>.out.<table capacity>.<blocked streams>.<whether
  # every section was taken as acknowledged at once>.
  IMPLEMENTATIONS.each do |implementation|
    define_method(:"test_#{implementation.tr("-", "_")}") do
      files = Dir[File.join(ENCODED, implementation, "*.out.*")].sort
      refute_empty files
      files.each do |path|
        name, table, blocked = File.basename(path).match(/\A(.+)\.out\.(\d+)\.(\d+)\.\d\z/).captures
        lists = decode_file(File.binread(path), table: Integer(table), blocked: Integer(blocked))
        assert_kind_of Hash, lists, "#{path}: #{lists.inspect}"
        assert_equal expected(name), lists.sort.map(&:last), path
      end
    end
  end

  private def expected(name) = (@expected ||= {})[name] ||= qif(File.join(QIFS_DIR, "qifs", "#{name}.qif"))

  # The exchange of RFC 9204 Appendix B; draft-examples.qif, which goes
  # with it, is of an older draft and does not match.
  def test_rfc9204_examples
    lists = decode_file(File.binread(File.join(ENCODED, "examples", "examples.out.220.100.1")), table: 220, blocked: 100)
    expected = {
      4 => [[":path", "/index.html"]],
      8 => [[":authority", "www.example.com"], [":path", "/sample/path"]],
      12 => [[":authority", "www.example.com"], [":path", "/"], ["custom-key", "custom-value"]]
    }
    assert_equal expected, lists.transform_values { |fields| fields.map { [_1.name, _1.value] } }
  end

  # Bytes that do not decode fail the connection. err9 and err10 refer to
  # static entries 0 and 62, past the end of HPACK's static table of 61
  # from 1, which the cases were made for; RFC 9204's has 99 from 0.
  def test_errors
    {
      1 => :DECOMPRESSION_FAILED, 2 => :DECOMPRESSION_FAILED, 3 => :DECOMPRESSION_FAILED, 4 => :DECOMPRESSION_FAILED,
      5 => :DECOMPRESSION_FAILED, 6 => :DECOMPRESSION_FAILED, 7 => :DECOMPRESSION_FAILED, 8 => :DECOMPRESSION_FAILED,
      11 => :ENCODER_STREAM_ERROR, 12 => :ENCODER_STREAM_ERROR
    }.each do |number, code|
      failure = decode_file(File.binread(File.join(QIFS_DIR, "encoded", "errors", "err#{number}")), table: 4096, blocked: 100)
      assert_kind_of QPACK::Failure, failure, "err#{number}"
      assert_equal QPACK::ErrorCode.const_get(code), failure.code, "err#{number}"
      assert_nil failure.stream_id, "err#{number}"
    end
    {9 => [":authority", ""], 10 => ["x-xss-protection", "1; mode=block"]}.each do |number, (name, value)|
      lists = decode_file(File.binread(File.join(QIFS_DIR, "encoded", "errors", "err#{number}")), table: 4096, blocked: 100)
      assert_equal({1 => [QPACK::Field.new(name: name.b, value: value.b)]}, lists, "err#{number}")
    end
  end
end
