#!/bin/bash
# Test the current package under a different kernel.
# Requires virtme and qemu to be installed.

set -eu
set -o pipefail

if [[ "${1:-}" = "--in-vm" ]]; then
  shift

  readonly home="$(mktemp --directory)"

  mount -t bpf bpf /sys/fs/bpf
  export CGO_ENABLED=0
  export HOME="$home"

  echo Running tests...
  /usr/local/bin/go test -mod=vendor -coverprofile="$1/coverage.txt" -covermode=atomic -v ./...
  touch "$1/success"
  exit 0
fi

# Force Go modules, so that vendoring and building are easier.
export GO111MODULE=on

# Pull all dependencies, so that we can run tests without the
# vm having network access.
go mod vendor

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi

readonly kernel="linux-${kernel_version}.bz"
readonly output="$(mktemp -d)"
readonly tmp_dir="$(mktemp -d)"

test -e "${tmp_dir}/${kernel}" || {
  echo Fetching ${kernel}
  curl --fail -L "https://github.com/newtools/ci-kernels/blob/master/${kernel}?raw=true" -o "${tmp_dir}/${kernel}"
}

echo Testing on ${kernel_version}
virtme-run --kimg "${tmp_dir}/${kernel}" --memory 2G --pwd --rwdir=/run/output="${output}" --script-sh "$(realpath "$0") --in-vm /run/output" --show-command --qemu-opts -monitor unix:qemu-monitor-socket,server,nowait

if [[ ! -e "${output}/success" ]]; then
  echo "Test failed on ${kernel_version}"
  exit 1
else
  echo "Test successful on ${kernel_version}"
  if [[ -v CODECOV_TOKEN ]]; then
    curl --fail -s https://codecov.io/bash > "${tmp_dir}/codecov.sh"
    chmod +x "${tmp_dir}/codecov.sh"
    "${tmp_dir}/codecov.sh" -f "${output}/coverage.txt"
  fi
fi

rm -r "${output}"
