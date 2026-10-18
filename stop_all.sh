#!/bin/bash
set -e
cd "$(dirname "$0")"
source scripts/install/runtime-path.sh
exec node scripts/launcher-control.js
