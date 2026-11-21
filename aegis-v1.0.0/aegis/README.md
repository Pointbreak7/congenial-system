# Aegis — Security Analytics Engine

A single-file C11 engine that applies the core Design & Analysis of Algorithms
toolkit (sorting, divide & conquer, greedy, dynamic programming, flow, string
matching) to a cybersecurity problem: ingest host log events, raise alerts,
correlate attack patterns, and plan containment under a budget.

**Version:** 1.0.0 · **Language:** C11 · **Dependencies:** none (libc only)

## Quick start
```sh
make          # build  -> build/aegis
make test     # 182 self-tests
make demo     # scripted walk through every menu option
make bench    # benchmarks, writes results.csv
make debug    # AddressSanitizer + UBSan build, then runs the tests
./build/aegis # interactive menu
```

## Repository layout
| Path | Purpose |
|---|---|
| `src/aegis.c` | The whole engine (algorithms, pipeline, demos, tests, benchmarks) |
| `Makefile` | build / test / demo / bench / debug / clean |
| `data/sample_logs.txt` | 203-line sample log, includes 6 deliberately bad lines |
| `data/results_reference.csv` | Reference benchmark output (machine-specific) |
| `scripts/demo.sh` | Demonstration script (used by `make demo`) |
| `docs/USER_GUIDE.md` | How to run and use it |
| `docs/DESIGN.md` | Architecture, data model, design decisions |
| `docs/COMPLEXITY_REPORT.md` | Time/space analysis with measured evidence |
| `docs/demo_output.txt` | Captured output of the demo script |
| `CHANGELOG.md` | Release notes |

## Algorithms covered
Merge sort, quicksort, binary search (iterative/recursive), lower-bound range
counting, maximum subarray, fast modular exponentiation, celebrity problem,
classical and Strassen matrix multiplication, activity selection, interval
partitioning, Huffman coding, Dijkstra, Prim, Kruskal, 0/1 knapsack (DP and
greedy), matrix-chain, LCS, optimal BST, Bellman-Ford, Floyd-Warshall, TSP (bitmask
DP), max-flow (Ford-Fulkerson/DFS), bipartite matching, Chinese Remainder
Theorem, naive / Rabin-Karp / finite-automaton / KMP string matching.

## Verified status (v1.0.0)
Built with `gcc -std=c11 -O2 -Wall -Wextra`: zero warnings. `make test`:
182 passed, 0 failed. `make debug` (ASan + UBSan): 182 passed, no sanitizer reports.
