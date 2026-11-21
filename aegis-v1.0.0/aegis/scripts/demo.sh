#!/bin/sh
# Aegis demonstration script: walks every menu option in order.
set -e
BIN=build/aegis
[ -x "$BIN" ] || make
step() { printf '\n########## %s ##########\n' "$1"; }
step "1  Sorting & searching";     printf '1\n0\n' | $BIN
step "2  Divide & conquer";        printf '2\n0\n' | $BIN
step "3  Greedy";                  printf '3\n0\n' | $BIN
step "4  Dynamic programming";     printf '4\n0\n' | $BIN
step "5  Flow & matching";         printf '5\n0\n' | $BIN
step "6  Signature matching";      printf '6\n0\n' | $BIN
step "7  Three scenarios";         printf '7\n0\n' | $BIN
step "L  Load sample log file";    printf 'L\ndata/sample_logs.txt\nV\n0\n' | $BIN
step "T  Self-tests";              printf 'T\n0\n' | $BIN
echo; echo "Demo complete. Run 'make bench' for benchmarks (writes results.csv)."
