#!/usr/bin/env bash
# Airlock end-to-end demo: keygen -> build -> verify -> import -> evidence -> serve.
#
#   scripts/demo.sh              full demo (ends with the gateway serving the dashboard)
#   scripts/demo.sh --no-serve   run everything but do not start the server
#
# Environment:
#   AIRLOCK_GGUF     path to the model file (default: first *.gguf found)
#   AIRLOCK_BUNDLE   path of the bundle to build (default: out/qwen3.airlock)
#   AIRLOCK_SKIP_EVAL=1          skip the adversarial prompt-injection suite
#   AIRLOCK_SKIP_TAMPER=1        skip the tamper demo
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BOLD="$(printf '\033[1m')"
BLUE="$(printf '\033[1;36m')"
GREEN="$(printf '\033[1;32m')"
RED="$(printf '\033[1;31m')"
OFF="$(printf '\033[0m')"

step() {
    printf '\n%s==> %s%s\n' "${BLUE}" "$*" "${OFF}"
}
ok() {
    printf '%s    %s%s\n' "${GREEN}" "$*" "${OFF}"
}
note() {
    printf '    %s\n' "$*"
}

SERVE=1
for arg in "$@"; do
    case "$arg" in
        --no-serve) SERVE=0 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    esac
done

GGUF="${AIRLOCK_GGUF:-}"
if [ -z "$GGUF" ]; then
    for cand in "$HOME"/models/*.gguf "$ROOT"/models/*.gguf "$ROOT"/out/*.gguf; do
        if [ -f "$cand" ]; then
            GGUF="$cand"
            break
        fi
    done
fi
if [ -z "$GGUF" ] || [ ! -f "$GGUF" ]; then
    echo "no model file found: set AIRLOCK_GGUF to a .gguf path" >&2
    exit 1
fi

BUNDLE="${AIRLOCK_BUNDLE:-$ROOT/out/qwen3.airlock}"
NAME="${AIRLOCK_NAME:-qwen3-airlock}"
mkdir -p "$ROOT/out"

printf '%sAirlock demo - signed offline AI bundle with self-generated accreditation evidence%s\n' \
    "$BOLD" "$OFF"
note "model   : $GGUF"
note "bundle  : $BUNDLE"

# ---------------------------------------------------------------- 1. keygen
step "1/7  keygen - ed25519 signing key"
python3 -m airlock keygen
ok "signing key ready"

# ---------------------------------------------------------------- 2. build
step "2/7  build - signed bundle (manifest + signature + sbom + scan)"
python3 -m airlock build \
    --gguf "$GGUF" \
    -o "$BUNDLE" \
    --name "$NAME" \
    --version "${AIRLOCK_VERSION:-0.1.0}" \
    --family "${AIRLOCK_FAMILY:-qwen3}" \
    --params "${AIRLOCK_PARAMS:-1.7b}" \
    --quant "${AIRLOCK_QUANT:-Q4_K_M}" \
    --license "${AIRLOCK_LICENSE:-apache-2.0}" \
    --source "${AIRLOCK_SOURCE:-ollama:qwen3:1.7b}"
ok "bundle built and signed"

# ---------------------------------------------------------------- 3. verify
step "3/7  verify - signature and per-artifact sha256"
python3 -m airlock verify "$BUNDLE"
ok "bundle verified"

# ---------------------------------------------------------------- 4. import
step "4/7  import - verify first, then install the model locally"
python3 -m airlock import "$BUNDLE"
ok "bundle imported"

# ---------------------------------------------------------------- 5. evidence
step "5/7  evidence - controls, SSP, POA&M, OSCAL-shaped results"
if [ "${AIRLOCK_SKIP_EVAL:-0}" != "1" ]; then
    note "running the adversarial prompt-injection suite (AI-EVAL) against the local model"
    if python3 -m airlock.evals --backend "${AIRLOCK_BACKEND:-ollama}" \
            --model "${AIRLOCK_MODEL:-$NAME}" --redact > "$ROOT/out/eval.log" 2>&1; then
        sed 's/^/    /' "$ROOT/out/eval.log"
        ok "injection suite measured and written to out/eval.json"
    else
        sed 's/^/    /' "$ROOT/out/eval.log"
        note "injection suite did not reach the threshold - reported as measured, not faked"
    fi
fi
python3 -m airlock evidence
ok "evidence written to out/evidence.json, out/ssp.html, out/poam.html, out/assessment-results.json"

# ---------------------------------------------------------------- 6. tamper
if [ "${AIRLOCK_SKIP_TAMPER:-0}" != "1" ]; then
    step "6/7  tamper - flip one byte of the model, the import must be refused"
    python3 scripts/tamper.py "$BUNDLE"
    TAMPERED="${BUNDLE%.airlock}.tampered.airlock"
    if python3 -m airlock import "$TAMPERED"; then
        echo "${RED}    UNEXPECTED: the tampered bundle was accepted${OFF}" >&2
        exit 1
    fi
    ok "tampered bundle refused, exactly as designed"
else
    step "6/7  tamper - skipped (AIRLOCK_SKIP_TAMPER=1)"
fi

# ---------------------------------------------------------------- 7. serve
if [ "$SERVE" -eq 1 ]; then
    step "7/7  serve - dashboard on http://127.0.0.1:${AIRLOCK_PORT:-8000}/"
    note "the dashboard polls /evidence.json every 2 s; exports are under /export/"
    exec python3 -m airlock serve
fi

step "done - artefacts in out/"
ls -la "$ROOT/out" | sed 's/^/    /'
