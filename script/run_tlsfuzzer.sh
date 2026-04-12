#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TLSFUZZER_DIR="${PROJECT_DIR}/tmp/tlsfuzzer"
PORT="${PORT:-4433}"

if [ ! -d "$TLSFUZZER_DIR" ]; then
  echo "tlsfuzzer not found. Cloning..."
  git clone https://github.com/tlsfuzzer/tlsfuzzer.git "$TLSFUZZER_DIR"
fi

# Start raiha fuzzing server
ruby -I"${PROJECT_DIR}/lib" "${SCRIPT_DIR}/fuzzing_server.rb" "$PORT" &
SERVER_PID=$!
sleep 1

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
    python3 "$script_path" -h localhost -p "$PORT" > /dev/null 2>&1; then
    echo "PASS"
    ((passed++))
  else
    exit_code=$?
    echo "FAIL (exit $exit_code)"
    ((failed++))
  fi
done

echo ""
echo "=== Results ==="
echo "Passed: $passed"
echo "Failed: $failed"
echo "Total:  $((passed + failed))"
