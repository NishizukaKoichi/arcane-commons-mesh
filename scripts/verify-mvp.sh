#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo run -p arcane-mesh-cli -- verify-mvp
