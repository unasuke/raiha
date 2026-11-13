#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TLSFUZZER_DIR="${PROJECT_DIR}/tmp/tlsfuzzer"
PORT="${PORT:-4433}"
# What each script and the server put out.
LOG_DIR="${PROJECT_DIR}/tmp/tlsfuzzer-logs"

# The commit of tlsfuzzer the results are of; change it to take a newer
# one, and run the scripts again.
TLSFUZZER_COMMIT=bf7f579dc0e65498cfb21b60e9b152f6bd84a3bf

if [ ! -d "$TLSFUZZER_DIR" ]; then
  echo "tlsfuzzer not found. Cloning..."
  git clone https://github.com/tlsfuzzer/tlsfuzzer.git "$TLSFUZZER_DIR"
fi
if [ "$(git -C "$TLSFUZZER_DIR" rev-parse HEAD)" != "$TLSFUZZER_COMMIT" ]; then
  git -C "$TLSFUZZER_DIR" fetch -q origin "$TLSFUZZER_COMMIT"
  git -C "$TLSFUZZER_DIR" checkout -q "$TLSFUZZER_COMMIT"
fi

# Start the fuzzing server of raiha
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"
(cd "$PROJECT_DIR" && exec bundle exec ruby "${SCRIPT_DIR}/fuzzing_server.rb" "$PORT") 2> "${LOG_DIR}/server.log" &
SERVER_PID=$!
sleep 3

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

SCRIPTS=(
  test-tls13-conversation.py
  test-tls13-ccs.py
  test-tls13-version-negotiation.py
  test-tls13-ecdhe-curves.py
  test-tls13-signature-algorithms.py
  test-tls13-symetric-ciphers.py
  test-tls13-hrr.py
  test-tls13-finished.py
  test-tls13-certificate-verify.py
  test-tls13-serverhello-random.py
  test-tls13-empty-alert.py
  test-tls13-record-layer-limits.py
  test-tls13-lengths.py
  test-tls13-zero-content-type.py
)

passed=0
failed=0
errored=0

for script in "${SCRIPTS[@]}"; do
  script_path="${TLSFUZZER_DIR}/scripts/${script}"
  if [ ! -f "$script_path" ]; then
    echo "SKIP: $script (not found)"
    continue
  fi

  echo -n "RUN:  $script ... "
  if PYTHONPATH="$TLSFUZZER_DIR" uv run --with "tlslite-ng==0.9.0b2" --with ecdsa --with six \
    python3 "$script_path" -h localhost -p "$PORT" > "${LOG_DIR}/${script%.py}.log" 2>&1; then
    echo "PASS"
    passed=$((passed + 1))
  else
    exit_code=$?
    echo "FAIL (exit $exit_code)"
    failed=$((failed + 1))
  fi
done

echo ""
echo "=== Results ==="
echo "Passed: $passed"
echo "Failed: $failed"
echo "Total:  $((passed + failed))"
