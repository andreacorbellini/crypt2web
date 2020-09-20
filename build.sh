#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

cd "$(dirname "$0")"

set -o xtrace

cargo build "$@" -p crypt2web-core
wasm-pack build --target web "$@" crypt2web-wasm
cargo build "$@"
