require "test_helper"
require "raiha/quic"

# The connection IDs of a worker: each tells, to every worker that shares
# the key, which worker issued it, while its first byte looks as random as
# the rest to anyone without the key.
class RaihaNextQUICWorkerConnectionIDsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  KEY = ("k" * 32).b

  def worker(id, count: 4, key: KEY, random: Random.new(id)) = QUIC::WorkerConnectionIDs.new(random, worker_id: id, worker_count: count, key:)

  def test_an_id_is_as_long_as_asked_and_binary
    id = worker(1).generate(8)
    assert_equal 8, id.bytesize
    assert_equal Encoding::BINARY, id.encoding
  end

  def test_every_other_worker_reads_back_the_worker_that_issued_an_id
    workers = Array.new(4) { |i| worker(i) }
    workers.each_with_index do |issuer, i|
      ids = Array.new(32) { issuer.generate(8) }
      workers.each_with_index do |reader, j|
        ids.each do |id|
          i == j ? assert_nil(reader.worker_of(id), "worker #{j} reading its own ID") : assert_equal(i, reader.worker_of(id), "worker #{j} reading worker #{i}'s ID")
        end
      end
    end
  end

  # The worker's ID does not show in the first byte: the IDs of one worker
  # begin with many different bytes.
  def test_the_first_byte_does_not_show_the_worker
    issuer = worker(2)
    firsts = Array.new(256) { issuer.generate(8).getbyte(0) }
    assert_operator firsts.uniq.size, :>, 100
  end

  # A worker that does not share the key cannot read an ID back: across many
  # IDs, what it reads is not the issuer.
  def test_another_key_does_not_read_back_the_worker
    issuer = worker(2)
    ids = Array.new(64) { issuer.generate(8) }
    reader = worker(0, key: ("x" * 32).b)
    refute ids.all? { |id| reader.worker_of(id) == 2 }
  end

  def test_no_worker_owns_what_falls_beyond_the_count
    issuer = worker(200, count: 256)
    ids = Array.new(64) { issuer.generate(8) }
    reader = worker(0, count: 4)
    ids.each { |id| assert_nil reader.worker_of(id) }
  end

  def test_an_id_too_short_to_carry_a_worker
    assert_raises(ArgumentError) { worker(0).generate(QUIC::WorkerConnectionIDs::MIN_LENGTH - 1) }
    assert_nil worker(0).worker_of(worker(1).generate(8).byteslice(0, 3))
  end

  def test_the_worker_and_the_count_are_checked
    assert_raises(ArgumentError) { worker(0, count: 0) }
    assert_raises(ArgumentError) { worker(0, count: 257) }
    assert_raises(ArgumentError) { worker(4, count: 4) }
    assert_raises(ArgumentError) { worker(-1, count: 4) }
  end

  def test_random_ids_belong_to_no_worker
    assert_nil QUIC::RandomConnectionIDs.new(Random.new(1)).worker_of("\x01\x02\x03\x04\x05\x06\x07\x08".b)
  end
end
