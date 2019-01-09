#!/bin/bash -x
# Adapted from https://github.com/kinvolk/stage1-builder/blob/master/examples/semaphore.sh
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -eu
set -o pipefail

# The kernel versions we want to run the tests on
readonly kernel_versions=("4.19.14")
readonly cache_dir="${SEMAPHORE_CACHE_DIR}"
readonly pkg_name="github.com/newtools/ebpf"

cache() {
  test -e "${cache_dir}/$1" || curl --fail -L "https://github.com/newtools/ci-kernels/blob/master/$1?raw=true" -o "${cache_dir}/$1"
}

# Install and cache QEMU
install-package qemu-system-x86
cache "initramfs.cpio.gz"

curl -s https://codecov.io/bash > codecov.sh
chmod +x codecov.sh

for kernel_version in "${kernel_versions[@]}"; do
  cache "linux-${kernel_version}"

  # timeout can be used to make sure tests finish in
  # a reasonable amount of time
  sudo timeout --foreground --kill-after=10 5m \
    qemu-system-x86_64 \
      -m 128 -smp 1 -enable-kvm \
      -virtfs local,id=host9p,path=/,security_model=passthrough,mount_tag=host9p \
      -kernel "${cache_dir}/linux-${kernel_version}" \
      -initrd "${cache_dir}/initramfs.cpio.gz" \
      -append "rootfstype=ramfs"
    # "mount -t tmpfs tmpfs /tmp &&
    #   mount -t bpf bpf /sys/fs/bpf &&
    #   mount -t debugfs debugfs /sys/kernel/debug/ &&
    #   cd /go/src/${pkg_name} &&
    #   go build -v ./... &&
    #   go test -coverprofile=coverage.txt -covermode=atomic -v ./..."

  # # Determine exit code from pod status due to rkt#2777
  # # https://github.com/coreos/rkt/issues/2777
  # test_status=$(sudo ./rkt/rkt status "$(<rkt-uuid)" | awk '/app-/{split($0,a,"=")} END{print a[2]}')
  # if [[ $test_status -ne 0 ]]; then
  #   exit "$test_status"
  # fi
  echo "Test successful on ${kernel_version}"
done

./codecov.sh
