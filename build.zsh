#!/bin/zsh

makc clean
OBJCOPY=/opt/homebrew/Cellar/binutils/2.46.0/bin/objcopy make test-sim-internal-flash-with-update V=1 POLICY_FILE=policy.bin