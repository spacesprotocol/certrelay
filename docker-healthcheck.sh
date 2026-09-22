#!/bin/sh
# certrelay container HEALTHCHECK.
#
# Two probes:
#
#   1. Liveness  - GET /health must answer 200 within 5s. Unmetered
#                  endpoint used by peer health checks and load balancers.
#                  Always runs.
#
#   2. Resolve   - If the operator sets CERTRELAY_HEALTHCHECK_HANDLE
#                  (e.g. "user@rad"), run the bundled `fabric` client
#                  against the local relay and assert it returns a zone
#                  whose subject matches the queried handle. Exercises
#                  the full client->relay->cert-chain->verify pipeline.
#
# Exit codes follow the docker HEALTHCHECK contract:
#   0 = healthy, 1 = unhealthy (any other value is treated as unhealthy).

set -eu

BIND="${CERTRELAY_BIND:-127.0.0.1}"
PORT="${CERTRELAY_PORT:-7778}"

# When the relay binds to a wildcard address (0.0.0.0 / ::), the
# healthcheck still has to connect to a concrete one from inside the
# container's own netns. Loopback is always correct in that case.
case "$BIND" in
    0.0.0.0|::|"") HEALTH_HOST="127.0.0.1" ;;
    *)             HEALTH_HOST="$BIND" ;;
esac

URL="http://${HEALTH_HOST}:${PORT}"

# -------- Probe 1: liveness --------------------------------------------
if ! wget -q --timeout=5 -O /dev/null "${URL}/health"; then
    echo "healthcheck: ${URL}/health did not respond within 5s" >&2
    exit 1
fi

# -------- Probe 2: subname resolution (opt-in) -------------------------
HANDLE="${CERTRELAY_HEALTHCHECK_HANDLE:-}"
if [ -n "$HANDLE" ]; then
    # The bundled fabric binary writes a single line of zone JSON to
    # stdout on success and "<handle>: not found" to stderr on a clean
    # miss (still exit 0). Network / decode errors exit non-zero.
    if ! out=$(fabric --seeds "$URL" --dev-mode "$HANDLE" 2>/dev/null); then
        echo "healthcheck: fabric resolve crashed for ${HANDLE} via ${URL}" >&2
        exit 1
    fi
    if [ -z "$out" ]; then
        echo "healthcheck: ${HANDLE} did not resolve via ${URL}" >&2
        exit 1
    fi
    # No jq in the runtime image; the zone JSON always contains both
    # the literal "handle" key and the requested handle string.
    case "$out" in
        *'"handle"'*"${HANDLE}"*) : ;;
        *)
            echo "healthcheck: unexpected resolve output for ${HANDLE}" >&2
            printf '%s' "$out" | head -c 200 >&2
            echo >&2
            exit 1
            ;;
    esac
fi

exit 0
