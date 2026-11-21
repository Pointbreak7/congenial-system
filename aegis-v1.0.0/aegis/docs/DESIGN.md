# Aegis Design Guide

## 1. Problem statement
Given a stream of host log events, (a) validate and order them, (b) raise
alerts, (c) detect multi-step attacks, and (d) recommend containment work under
a fixed analyst-hour budget. Each stage is solved with a classical algorithm
chosen to fit the sub-problem, so the engine doubles as a DAA showcase.

## 2. Architecture
```
 log file / built-in generator
            |
     load_logs / default_events      <- parse + event_valid() (reject bad lines)
            |
         analyze()
   +--------+---------+-----------+
   |        |         |           |
merge_sort_ev  build_index  build_alerts   build_items
 (time order)  (counts)     (severity rule   (patch/DLP actions:
                             + signatures)    cost, risk removed)
            |
   demos (1-7), V indicators, benchmarks (8), self-tests (T)
```
Everything lives in `src/aegis.c`, in this order: constants and types, generic
algorithm library, event-specific variants, graph/DP/flow/string algorithms,
global state and pipeline, benchmarks, tests, demos, menu.

## 3. Data model
| Type | Fields | Notes |
|---|---|---|
| `LogEvent` | time (HHMM), host, type, severity | 16 bytes |
| `Host` | name, criticality, patch_cost, dlp_cost | constant table of 6 |
| `Signature` | name, pattern, severity | constant table of 4 |
| `Alert` | time, host, type, severity, rule | `rule = -1` for a severity alert, else signature index |
| `Graph` | n, `w[MAXV][MAXV]` | adjacency matrix, `INF` = no edge |
| `EventIndex` | by_host, by_type, by_sev | counting index built in one pass |

Global state is static arrays (`events[MAXLOG]`, `alerts[MAXALERT]`) with
explicit counters (`nev`, `nal`, `rejected`, `dropped`). No heap is held across
menu actions; temporary buffers are freed in the function that allocates them.

## 4. Key design decisions
1. **Events as letters.** Each host's event stream is projected to a string over
   {L, F, S, M, X}. Attack detection becomes substring search, which lets four
   different matchers be compared on identical input and cross-checked in tests.
2. **Total order for events.** `ev_cmp` orders by time, then host, type, severity,
   so merge sort and quicksort must produce byte-identical output, which tests
   assert with `memcmp`.
3. **Middle-element pivot for event quicksort** (`quick_sort_ev`), versus the
   last-element pivot in the integer version (`quick_sort`). The pair is kept on
   purpose: the benchmark's adversarial case shows the cost of the weaker choice.
4. **Matrix graphs, `MAXV = 10`.** Keeps every graph algorithm to a few lines and
   makes complexity statements in terms of V simple. The cost is O(V^2) space and
   a hard size cap.
5. **Budgeted containment as 0/1 knapsack.** Weight = analyst hours, value = risk
   removed (`severity * host criticality`). DP is exact; the ratio-greedy is kept
   to show where greedy fails (default dataset: DP 374 vs greedy 354).
6. **Validation first.** `event_reason` returns a human-readable cause; `load_logs`
   only admits events that pass, and the rejected count feeds the KPIs.
7. **Determinism.** Generators use a private LCG (`lcg_state`), reseeded before
   use, so demos and tests give identical output on every run. Benchmarks use
   `srand` with fixed seeds.
8. **Self-verifying algorithms.** Tests compare against brute force (knapsack over
   all subsets), the C library (`qsort`), or an alternate algorithm (Dijkstra vs
   Bellman-Ford, four string matchers, classical vs Strassen).

## 5. Module map
| Concern | Functions |
|---|---|
| Sorting / searching | `merge_sort`, `quick_sort`, `*_ev` variants, `bsearch_iter/rec`, `lower_bound`, `count_in_range` |
| Divide & conquer | `max_subarray`, `power_mod`, `find_celebrity`, `mat_strassen` |
| Greedy | `activity_select`, `interval_partition`, `huffman`, `dijkstra`, `prim`, `kruskal`, `knapsack_greedy` |
| Dynamic programming | `knapsack_dp`, `matrix_chain`, `lcs`, `optimal_bst`, `bellman_ford`, `floyd_warshall`, `tsp_dp` |
| Flow / matching | `max_flow`, `bipartite_match` |
| Number theory / strings | `crt`, `naive_search`, `rk_search`, `fa_search`, `kmp_search` |
| Pipeline | `load_logs`, `default_events`, `analyze`, `build_alerts`, `build_items` |
| Harness | `run_benchmarks`, `run_tests`, `demo_*`, `scenarios`, `menu` |

## 6. Error handling
- Bad input lines are rejected, counted, and never stored.
- Algorithms return sentinels for impossible input (`-1`, `INF`) rather than
  aborting: disconnected MST, over-size DP, negative budget, no celebrity.
- Alert overflow increments `dropped` and prints a warning instead of overwriting.
- `malloc` results are not checked (see Known limitations).

## 7. Known limitations and future work
- `malloc` return values are unchecked; acceptable for the data sizes used.
- `quick_sort` degrades to O(n^2) on sorted input and recurses to depth O(n).
- `mat_strassen` is correct only for sizes `c * 2^k` (c <= 16); other sizes
  such as 50 or 100 give wrong results silently. Pad to the next valid size.
- `#` lines in log files count as rejected.
- Files longer than `MAXLOG` are truncated silently.
- Single translation unit: splitting into headers/modules would help reuse.
- Insertion-sort helpers (`order_by`, `ratio_order`, `kruskal` edge sort) keep the
  greedy routines O(n^2); swapping in `merge_sort` on indices gives O(n log n).
