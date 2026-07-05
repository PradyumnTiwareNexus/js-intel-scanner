#!/usr/bin/env bash
# Quick launcher: python -m backend.cli scan <domain>  (or pass any CLI args through)
set -e
python -m backend.cli "$@"
