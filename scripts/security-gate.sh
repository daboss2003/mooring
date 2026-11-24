#!/usr/bin/env bash
# security-gate.sh — the §15 Security Assurance Program entrypoint (milestone M12).
#
# It runs the IN-REPO gates (always, fail-closed: these need no external binary and
# are the shippability bar) and then each EXTERNAL tool IF it is installed (CI
# installs them; a dev box without them still gets the in-repo gates). A missing
# external tool is reported as SKIPPED, never silently passed.
#
# Usage:
#   scripts/security-gate.sh            # in-repo gates + any installed tools
#   FUZZTIME=30s scripts/security-gate.sh   # longer fuzz smoke (default 10s)
#
# Exit non-zero if any RUN gate fails. SKIPPED tools do not fail the gate locally,
# but CI must install them (see the matrix at the bottom) so they become RUN there.
set -uo pipefail
cd "$(dirname "$0")/.."

FUZZTIME="${FUZZTIME:-10s}"
fail=0
have() { command -v "$1" >/dev/null 2>&1; }
hr() { printf '\n=== %s ===\n' "$1"; }
run() { # run <label> <cmd...>
	local label="$1"; shift
	printf -- '--- %s\n' "$label"
	if "$@"; then printf 'PASS  %s\n' "$label"; else printf 'FAIL  %s\n' "$label"; fail=1; fi
}
skip() { printf 'SKIP  %s (not installed)\n' "$1"; }

hr "In-repo gates (always run; fail-closed)"
# go vet + the full test suite — this is where the Phase-1 custom static rules
# (internal/security), the Phase-3 authz route-posture matrix (internal/web), the
# Layer-A SBD invariants (internal/edge), and every other unit/abuse test live.
run "go vet ./..."            go vet ./...
run "go build ./..."          go build ./...
run "go test ./..."           go test ./... -count=1

hr "Phase-3 fuzz smoke (${FUZZTIME} each; zero panics/OOM/hangs)"
fuzz() { # fuzz <pkg> <FuzzName>
	run "fuzz $2" go test "./$1/" -run '^$' -fuzz "^$2\$" -fuzztime="$FUZZTIME"
}
fuzz internal/ops       FuzzParseDescriptor
fuzz internal/ops       FuzzParseHealth
fuzz internal/ops       FuzzParseQueues
fuzz internal/opsclient FuzzValidateRelPath
fuzz internal/web       FuzzSingleXFF
fuzz internal/web       FuzzConfinedUnder
fuzz internal/web       FuzzVerifyWebhookSig
# Security logs: every line an app, the edge or a local user writes is hostile input.
fuzz internal/siem/query  FuzzParse
fuzz internal/siem/redact FuzzRedact
fuzz internal/siem/parse  FuzzAppLine
fuzz internal/siem/parse  FuzzEdgeAccess
fuzz internal/siem/parse  FuzzAuthLog
fuzz internal/siem/parse  FuzzJournal
fuzz internal/siem/feeds  FuzzParseSpamhaus
fuzz internal/siem/feeds  FuzzParseTor
fuzz internal/siem/feeds  FuzzParseDShield
fuzz internal/siem/feeds  FuzzDecodeSnapshot
fuzz internal/siem/detect FuzzEvent

hr "Phase-1 external static tools (run if installed)"
if have govulncheck; then run "govulncheck (zero reachable)" govulncheck ./...; else skip govulncheck; fi
if have staticcheck;  then run "staticcheck"                  staticcheck ./...;  else skip staticcheck;  fi
if have gosec;        then run "gosec"                        gosec -quiet ./...; else skip gosec;        fi
if have gitleaks;     then run "gitleaks (full history)"      gitleaks detect --no-banner --redact; else skip gitleaks; fi
if have trivy;        then run "trivy fs (HIGH/CRITICAL)"     trivy fs --quiet --severity HIGH,CRITICAL --exit-code 1 .; else skip trivy; fi

hr "Result"
if [ "$fail" -ne 0 ]; then
	echo "SECURITY GATE: FAILED"
	exit 1
fi
echo "SECURITY GATE: in-repo gates PASSED (ensure CI installs the SKIPPED tools)."

# CI must additionally provide, per §15 (out of scope for this script's box):
#   - govulncheck / staticcheck / gosec / gitleaks / trivy / grype installed (→ RUN)
#   - syft SBOM + cosign/SLSA provenance on the release artifact
#   - DAST (authenticated + unauthenticated) against a deployed instance
#   - the independent pentest cadence + systemd-posture drift-check
