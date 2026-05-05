#!/usr/bin/env bash
#
# Build Cargo test binaries and run them inside one virtme-ng VM with
# dummy_hcd USB gadget support.
#
# Usage mirrors the relevant parts of `cargo test`:
#   .misc/cargo-test-vm.sh [cargo-test-args...] -- [test-binary-args...]
#
# Example:
#   .misc/cargo-test-vm.sh --release --all-features -- \
#     --nocapture --test-threads=1 --skip uac1 --skip uac2 --skip video
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cargo_args=()
test_args=()
seen_separator=false

for arg in "$@"; do
    if [ "$seen_separator" = false ] && [ "$arg" = "--" ]; then
        seen_separator=true
        continue
    fi

    if [ "$seen_separator" = true ]; then
        test_args+=("$arg")
    else
        cargo_args+=("$arg")
    fi
done

if [ "${#cargo_args[@]}" -eq 0 ]; then
    cargo_args=(--release --all-features)
fi

if [ -z "${KERNEL_TARBALL:-}" ]; then
    KERNEL_TARBALL="$(ls -t "$SCRIPT_DIR"/kernel-*.tar.zst 2>/dev/null | head -1 || true)"
fi

if [ -z "$KERNEL_TARBALL" ] || [ ! -f "$KERNEL_TARBALL" ]; then
    echo "ERROR: no kernel tarball found." >&2
    echo "Build one with: .misc/build-kernel.sh" >&2
    echo "Or set KERNEL_TARBALL=/path/to/kernel-*.tar.zst" >&2
    exit 1
fi

STAGING="${KERNEL_STAGING:-/tmp/ci-kernel-runner}"

if [ ! -f "$STAGING/boot/bzImage" ]; then
    mkdir -p "$STAGING"
    tar -I zstd -xf "$KERNEL_TARBALL" -C "$STAGING"
fi

BZIMAGE="$STAGING/boot/bzImage"
ARTIFACTS_JSON="$(mktemp /tmp/cargo-test-artifacts.XXXXXX.json)"
TEST_LIST="$(mktemp /tmp/cargo-test-binaries.XXXXXX.tsv)"
INIT_SCRIPT="$(mktemp /tmp/ci-vm-init.XXXXXX.sh)"

cleanup() {
    rm -f "$ARTIFACTS_JSON" "$TEST_LIST" "$INIT_SCRIPT"
}
trap cleanup EXIT

cd "$REPO_DIR"

echo "Building test binaries..."
cargo test "${cargo_args[@]}" --no-run --message-format=json > "$ARTIFACTS_JSON"

python3 - "$ARTIFACTS_JSON" "$TEST_LIST" "$REPO_DIR/Cargo.toml" <<'PY'
import json
import os
import sys

artifacts_path, test_list_path, manifest_path = sys.argv[1:]
manifest_path = os.path.realpath(manifest_path)
tests = []
seen = set()

with open(artifacts_path, encoding="utf-8") as artifacts:
    for line in artifacts:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        if message.get("reason") != "compiler-artifact":
            continue
        if os.path.realpath(message.get("manifest_path", "")) != manifest_path:
            continue
        if not message.get("profile", {}).get("test"):
            continue

        executable = message.get("executable")
        if not executable or executable in seen:
            continue

        target = message.get("target", {})
        name = target.get("name", os.path.basename(executable))
        src_path = target.get("src_path", "")
        kind = target.get("kind", [])
        rank = 0 if "lib" in kind else 1

        seen.add(executable)
        tests.append((rank, src_path, name, executable))

tests.sort()

if not tests:
    raise SystemExit("no test binaries found")

with open(test_list_path, "w", encoding="utf-8") as test_list:
    for _rank, _src_path, name, executable in tests:
        test_list.write(f"{name}\t{executable}\n")

print(f"Found {len(tests)} test binaries")
PY

{
    printf '#!/bin/bash\n'
    printf 'set -euo pipefail\n'
    printf '\n'
    printf 'TEST_LIST=%q\n' "$TEST_LIST"
    printf 'TEST_ARGS=('
    for arg in "${test_args[@]}"; do
        printf ' %q' "$arg"
    done
    printf ' )\n'
    printf '\n'
    printf '# Forwarded environment variables from host.\n'
    while IFS='=' read -r key value; do
        case "$key" in
            USB_GADGET_*|RUST_*)
                printf 'export %s=%q\n' "$key" "$value"
                ;;
        esac
    done < <(env)

    cat <<'INITEOF'

modprobe configfs
modprobe libcomposite
modprobe dummy_hcd is_super_speed=Y

if ! grep -q ' /sys/kernel/config ' /proc/mounts; then
    mount -t configfs configfs /sys/kernel/config
fi

for m in \
    usb_f_fs usb_f_acm usb_f_serial usb_f_ecm usb_f_eem usb_f_ncm \
    usb_f_rndis usb_f_ecm_subset usb_f_hid usb_f_mass_storage \
    usb_f_printer usb_f_midi usb_f_uac1 usb_f_uac2 usb_f_uvc \
    usb_f_ss_lb; do
    modprobe "$m" 2>/dev/null || true
done

while IFS=$'\t' read -r test_name test_binary; do
    if [ -z "$test_binary" ]; then
        continue
    fi

    echo
    echo "=== Running $test_name ($test_binary) ==="
    "$test_binary" "${TEST_ARGS[@]}"
done < "$TEST_LIST"
INITEOF
} > "$INIT_SCRIPT"
chmod +x "$INIT_SCRIPT"

echo "Running test binaries in one VM..."
vng \
    --run "$BZIMAGE" \
    --rw \
    --cpus "${VM_CPUS:-$(nproc 2>/dev/null || echo 4)}" \
    --memory "${VM_MEMORY:-4G}" \
    --exec "$INIT_SCRIPT"
