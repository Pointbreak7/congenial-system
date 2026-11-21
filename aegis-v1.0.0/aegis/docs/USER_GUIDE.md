# Aegis User Guide

## 1. Build and run
Requires `gcc` (or any C11 compiler) and `make`.
```sh
make
./build/aegis
```
The program starts with a built-in deterministic dataset of 200 events
(seeded generator, with one kill chain and one brute-force pattern planted),
so every menu option works immediately.

## 2. Menu
| Key | What it shows |
|---|---|
| `1` | Sorting events by time (merge vs quick), binary search, time-range counts, host/severity indexes |
| `2` | Divide & conquer: worst risk stretch (max subarray), Diffie-Hellman via fast exponentiation, log-collector (celebrity), classical vs Strassen timing |
| `3` | Greedy: analyst scheduling, Huffman coding of event types, shortest attack path (Dijkstra), cheapest cabling (Prim/Kruskal) |
| `4` | Dynamic programming: containment plan under budget (DP vs greedy knapsack), matrix chain, LCS, optimal BST, Bellman-Ford, Floyd-Warshall, TSP |
| `5` | Max traffic flow and analyst-to-incident matching |
| `6` | CRT, signature matching with four algorithms, correlated incidents |
| `7` | Three scenarios: normal operation, capacity shock, large-data stress |
| `8` | Benchmarks; writes `results.csv` in the current directory |
| `L` | Load a log file (prompts for a path) |
| `V` | Validation demo and service indicators (KPIs) for the current dataset |
| `T` | Run the 182 self-tests |
| `0` | Exit |

Non-interactive use: pipe keystrokes, e.g. `printf '4\n0\n' | ./build/aegis`.

## 3. Log file format
One event per line, whitespace separated:
```
time host type severity      e.g.  1020 3 3 4
time                         e.g.  1415      (host/type/severity are generated)
```
- `time`: HHMM, 0000-2359, minutes 00-59
- `host`: 0 gateway, 1 firewall, 2 web, 3 database, 4 siem, 5 backup
- `type`: 0 login-ok, 1 login-fail, 2 port-scan, 3 malware, 4 exfiltration
- `severity`: 1-5

Invalid lines are rejected and counted, never loaded. A time-only line has
its other fields filled deterministically (fixed seed), so reloading the same
file gives the same result.

Try it:
```sh
printf 'L\ndata/sample_logs.txt\nV\n0\n' | ./build/aegis
# loaded 197 valid events, rejected 6 invalid lines
```

## 4. Alert rules
- **Severity alert:** any event with severity >= 4.
- **Correlated incident:** per host, events become a letter string
  (L, F, S, M, X) and four signatures are searched: `FFF` brute-force (sev 3),
  `SM` scan-then-malware (4), `MX` malware-then-exfiltration (5),
  `SMX` full kill chain (5).

## 5. Reading the indicators (`V`)
Events accepted/rejected, high-severity alerts per hour, correlated incident
count, busiest host, peak alert hour, and *risk coverage*: how much of the total
removable risk the budgeted containment plan covers (budget = half the total
action cost).

## 6. Limits and known behaviour
- Capacity: 100000 events (`MAXLOG`); extra lines in a file are ignored.
- Alerts: 50000 (`MAXALERT`); overflow is counted and a warning is printed.
- Lines starting with `#` are **not** treated as comments; they count as rejected.
- Strassen requires the matrix size to be `c * 2^k` with `c <= 16` (benchmarks use powers of two).
- Graph algorithms are capped at `MAXV = 10` vertices; TSP at 10 sites.
- `make bench` timings vary by machine; use them for comparison, not as absolutes.

## 7. Troubleshooting
| Symptom | Fix |
|---|---|
| `could not read file` | Path is wrong or relative to the wrong directory; run from the repo root |
| `cannot write results.csv` | Run from a writable directory |
| `make: gcc not found` | `make CC=clang` or install a C compiler |
