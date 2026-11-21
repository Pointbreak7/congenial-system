# Aegis Complexity Report

Notation: N events, H hosts (6), n input size, V vertices (<=10), E edges, W knapsack
capacity, m pattern length, f max-flow value. All bounds are for the code as
written, not the textbook ideal; where they differ, the reason is stated.

## 1. Analytical summary
| Algorithm | Time | Extra space | Notes |
|---|---|---|---|
| `merge_sort` / `merge_sort_ev` | Theta(n log n) all cases | O(n) | stable |
| `quick_sort` (last pivot) | avg O(n log n), **worst O(n^2)** | O(log n) avg, **O(n) worst** stack | worst on sorted input |
| `quick_sort_ev` (middle pivot) | avg O(n log n), worst O(n^2) | O(log n) avg | sorted input is no longer worst |
| `bsearch_iter` / `bsearch_rec` | O(log n) | O(1) / O(log n) | |
| `lower_bound`, `count_in_range` | O(log n) | O(1) | two lower bounds per range |
| `max_subarray` | T(n)=2T(n/2)+O(n) = O(n log n) | O(log n) | Kadane would be O(n) |
| `power_mod` | O(log e) | O(log e) stack | |
| `find_celebrity` | candidate O(n) + verify O(n) = O(n) | O(log n) | |
| `mat_classic` | O(n^3) | O(1) | |
| `mat_strassen` | O(n^log2 7) ~ O(n^2.807) | ~6.3 n^2 ints | CUTOFF=16 |
| `activity_select` | O(n^2) | O(n) | insertion-sort by finish; O(n log n) with a real sort |
| `interval_partition` | O(n^2) | O(n) | sort + O(n * rooms) scan |
| `huffman` | O(n^2) | O(n) | linear min-scan, n <= 16 |
| `dijkstra` | O(V^2) | O(V) | array version |
| `prim` | O(V^2) | O(V) | |
| `kruskal` | O(E^2) | O(E) | insertion sort of edges, E <= V^2 |
| `knapsack_dp` | Theta(nW) | Theta(nW) | pseudo-polynomial |
| `knapsack_greedy` | O(n^2) | O(n) | not optimal for 0/1 |
| `matrix_chain` | Theta(n^3) | Theta(n^2) | |
| `lcs` | Theta(nm) | Theta(nm) | |
| `optimal_bst` | Theta(n^3) | Theta(n^2) | range sums recomputed in the inner loop |
| `bellman_ford` | O(V^3) | O(V) | O(VE) on lists; matrix makes E=V^2 |
| `floyd_warshall` | Theta(V^3) | Theta(V^2) | |
| `tsp_dp` | Theta(2^V V^2) | Theta(2^V V) | static 40 KB table |
| `max_flow` (DFS augmenting) | O(f V^2) | O(V^2) | pseudo-polynomial in capacities |
| `bipartite_match` | O(L R^2) | O(R) | matrix form; O(VE) with lists |
| `crt` | O(k^2 + k log M) | O(1) | pairwise gcd check |
| `naive_search` | O(nm) worst | O(1) | |
| `rk_search` | avg O(n+m), worst O(nm) | O(1) | collision verified with `strncmp` |
| `fa_search` | O(256 m) build + O(n) match | O(256 m) | |
| `kmp_search` | O(n+m) | O(m) | |
| Pipeline `analyze` | O(N log N) sort + O(N) index + O(H S N) alert scan | O(N) | S = 4 signatures |
| `load_logs` | O(N) | O(1) | |

## 2. Measured evidence
Single run on the build sandbox (`gcc -O2`, `clock()` CPU time). Absolute times
will differ on your machine; ratios are what matter. Full table:
`data/results_reference.csv`.

| Experiment | Result | What it shows |
|---|---|---|
| Sort 100000 ints, random | merge 8.65 ms, quick 6.14 ms | quick wins on random data (no copy) |
| Sort 20000 ints, **already sorted** | merge 0.36 ms, quick **108.29 ms** | ~300x slowdown: the O(n^2) worst case is real |
| Sort 100000 events | merge 13.90 ms, quick 11.74 ms | struct moves narrow the gap; merge needs 1.6 MB buffer |
| Search random 1M text, 8-char pattern | naive 4.72, RK 8.26, automaton 2.70, KMP 5.85 ms | on random text naive is fine; RK's modulo cost shows |
| Search `a`x300000 for `a`x300+`b` | **naive 36.61**, RK 2.44, automaton 1.02, KMP 1.51 ms | naive's O(nm) collapses; linear methods hold |
| Matrix 32 / 64 / 128 / 256 | classic 0.020 / 0.140 / 1.773 / 16.432 ms; Strassen 0.021 / 0.107 / 0.828 / 6.325 ms | crossover near 32-64 at CUTOFF=16; 2.6x faster at 256 |
| Strassen scratch memory at 256 | 1,653,760 bytes | matches ~6.3 n^2 ints |
| Knapsack n=20 | DP 0.003 ms, 13,692 B table; greedy ~0 ms | on this random instance greedy tied the optimum (365 = 365) |

Doubling check for classic multiply: 64->128 is x12.7, 128->256 is x9.3, near the
expected x8 for n^3 (cache effects add noise). Strassen: 128->256 is x7.6, near
the expected x7.

## 3. Where greedy is not enough
Default dataset containment plan, budget 41 h: DP removes **374** risk units,
greedy-by-ratio only **354** (5.3% less). The ratio rule fills the knapsack with
cheap high-ratio items and strands unused hours. Test suite checks
`greedy <= optimal` on 30 random instances plus the exact brute-force optimum on
the live data.

## 4. Space accounting
- Static: `events` 1.6 MB (100000 x 16 B), `alerts` 1.0 MB (50000 x 20 B).
- `tsp_dp` table: 1024 x 10 ints = 40 KB.
- Automaton table: (m+1) x 256 x 4 B; 9,216 B for m=8, 309,248 B for m=300.

## 5. Correctness and risk findings
| Finding | Impact | Mitigation |
|---|---|---|
| `quick_sort` last-element pivot | O(n^2) time and O(n) stack on sorted input | middle/median pivot or random pivot; already used in `quick_sort_ev` |
| `mat_strassen` wrong for n=50, 100 (verified) | silent wrong output | require `c*2^k` sizes or pad |
| Greedy helpers use insertion sort | O(n^2) where O(n log n) is possible | sort indices with merge sort |
| `#` lines counted as rejected | inflates reject count | document, or skip lines starting with `#` |
| Unchecked `malloc` | crash on allocation failure | add NULL checks if sizes grow |

Test coverage: 182 assertions across sorting, D&C, greedy, DP, flow, strings
and the record pipeline, including empty/one-element inputs, invalid events,
negative cycles, disconnected graphs and non-coprime CRT moduli. Also clean under
AddressSanitizer + UndefinedBehaviorSanitizer (`make debug`).
