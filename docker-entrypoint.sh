#!/bin/sh
# certrelay container entrypoint.
#
# Responsibilities:
#   1. Apply container-friendly defaults for the CERTRELAY_* env vars when
#      the caller has not set them explicitly. The defaults mirror the
#      shape of setup-spaced-prod-env.sh so that "source that file, then
#      `docker run --env-file ...`" Just Works.
#   2. Make sure CERTRELAY_DATA_DIR exists and is writable by the current
#      uid before we exec the relay (the relay also tries to create it,
#      but failing here gives a clearer error message than a panic later).
#   3. Print a one-shot summary of the env certrelay will actually see, so
#      operators can verify the configuration was wired through the
#      container correctly.
#   4. exec the binary so signals from tini (PID 1) reach it directly.

set -eu

: "${CERTRELAY_CHAIN:=mainnet}"
: "${CERTRELAY_DATA_DIR:=/data}"
: "${CERTRELAY_BIND:=0.0.0.0}"
: "${CERTRELAY_PORT:=7778}"
: "${CERTRELAY_BOOTSTRAP:=false}"
: "${CERTRELAY_ANCHOR_REFRESH:=300}"

export CERTRELAY_CHAIN CERTRELAY_DATA_DIR CERTRELAY_BIND CERTRELAY_PORT \
       CERTRELAY_BOOTSTRAP CERTRELAY_ANCHOR_REFRESH

# Ensure the data dir is usable. The relay will create it too, but doing it
# here gives a precise error if a volume was mounted with the wrong owner.
if ! mkdir -p "${CERTRELAY_DATA_DIR}" 2>/dev/null; then
    echo "certrelay: cannot create data dir ${CERTRELAY_DATA_DIR}" >&2
    exit 1
fi
if [ ! -w "${CERTRELAY_DATA_DIR}" ]; then
    echo "certrelay: data dir ${CERTRELAY_DATA_DIR} is not writable by uid $(id -u)" >&2
    echo "          (chown the host volume to the 'certrelay' user inside the image)" >&2
    exit 1
fi

# Redact secrets that may appear in URLs (basic auth) before logging.
redact() {
    # turns scheme://user:pass@host  ->  scheme://***:***@host
    printf '%s' "${1:-}" | sed -E 's#(://)[^:@/]+:[^@/]+@#\1***:***@#g'
}

cat <<EOF
certrelay: starting with effective configuration
  CERTRELAY_CHAIN            = ${CERTRELAY_CHAIN}
  CERTRELAY_DATA_DIR         = ${CERTRELAY_DATA_DIR}
  CERTRELAY_BIND             = ${CERTRELAY_BIND}
  CERTRELAY_PORT             = ${CERTRELAY_PORT}
  CERTRELAY_SELF_URL         = ${CERTRELAY_SELF_URL:-<unset>}
  CERTRELAY_SPACED_RPC_URL   = $(redact "${CERTRELAY_SPACED_RPC_URL:-<unset>}")
  CERTRELAY_REMOTE_IP_HEADER = ${CERTRELAY_REMOTE_IP_HEADER:-<unset>}
  CERTRELAY_BOOTSTRAP        = ${CERTRELAY_BOOTSTRAP}
  CERTRELAY_ANCHOR_REFRESH   = ${CERTRELAY_ANCHOR_REFRESH}
  CERTRELAY_SEEDS            = ${CERTRELAY_SEEDS:-<builtin mainnet / none off-mainnet>}
  CERTRELAY_CONFIG           = ${CERTRELAY_CONFIG:-<unset>}
  RUST_LOG                   = ${RUST_LOG:-info}
EOF

# If the user passed extra args (or only flags), forward them to certrelay.
# If they passed nothing or just "certrelay", run the binary with no extra
# args - all configuration comes from the env vars above.
case "${1:-}" in
    ""|certrelay)
        shift 2>/dev/null || true
        exec certrelay "$@"
        ;;
    -*)
        exec certrelay "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
