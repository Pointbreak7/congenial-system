#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>

#define INF      1000000000
#define MAXV     10
#define MAXN     20
#define MAXSYM   16
#define HUF_LEN  20
#define MAXLOG    100000
#define MAXALERT  50000
#define NHOSTS    6
#define NTYPES    5
#define NSIGS     4
#define NITEMS    (2 * NHOSTS)
#define ALERT_SEV 4
#define SCHED_MAX 100

typedef struct { int n; int w[MAXV][MAXV]; } Graph;
void graph_init(Graph *g, int n);
void graph_edge(Graph *g, int u, int v, int w);
void graph_edge2(Graph *g, int u, int v, int w);

enum { EV_LOGIN, EV_FAIL, EV_SCAN, EV_MALWARE, EV_EXFIL };

typedef struct { int time, host, type, severity; } LogEvent;
typedef struct { const char *name; int criticality, patch_cost, dlp_cost; } Host;
typedef struct { const char *name, *pattern; int severity; } Signature;
typedef struct { int time, host, type, severity, rule; } Alert;

static const Host hosts[NHOSTS] = {

    {"gateway",   3,  6, 4},
    {"firewall",  4,  8, 5},
    {"web",       3, 10, 6},
    {"database",  5, 14, 9},
    {"siem",      4,  7, 5},
    {"backup",    2,  5, 3},
};
static const char *const type_name[NTYPES] = {"login-ok", "login-fail", "port-scan", "malware", "exfiltration"};
static const char type_char[NTYPES] = {'L', 'F', 'S', 'M', 'X'};
static const Signature sigs[NSIGS] = {
    {"brute-force",        "FFF", 3},
    {"scan-then-malware",  "SM",  4},
    {"malware-then-exfil", "MX",  5},
    {"full-kill-chain",    "SMX", 5},
};

static void merge(int a[], int tmp[], int lo, int mid, int hi) {
    int i = lo, j = mid + 1, k = lo;
    while (i <= mid && j <= hi) tmp[k++] = (a[i] <= a[j]) ? a[i++] : a[j++];
    while (i <= mid) tmp[k++] = a[i++];
    while (j <= hi)  tmp[k++] = a[j++];
    for (k = lo; k <= hi; k++) a[k] = tmp[k];
}
static void msort(int a[], int tmp[], int lo, int hi) {
    if (lo >= hi) return;
    int mid = (lo + hi) / 2;
    msort(a, tmp, lo, mid);
    msort(a, tmp, mid + 1, hi);
    merge(a, tmp, lo, mid, hi);
}
void merge_sort(int a[], int n) {
    if (n < 2) return;
    int *tmp = malloc(n * sizeof(int));
    msort(a, tmp, 0, n - 1);
    free(tmp);
}

void quick_sort(int a[], int lo, int hi) {
    if (lo >= hi) return;
    int pivot = a[hi], i = lo - 1, t;
    for (int j = lo; j < hi; j++)
        if (a[j] < pivot) { i++; t = a[i]; a[i] = a[j]; a[j] = t; }
    t = a[i + 1]; a[i + 1] = a[hi]; a[hi] = t;
    quick_sort(a, lo, i);
    quick_sort(a, i + 2, hi);
}

int bsearch_iter(const int a[], int n, int key) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] == key) return mid;
        if (a[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}
int bsearch_rec(const int a[], int lo, int hi, int key) {
    if (lo > hi) return -1;
    int mid = lo + (hi - lo) / 2;
    if (a[mid] == key) return mid;
    if (a[mid] < key) return bsearch_rec(a, mid + 1, hi, key);
    return bsearch_rec(a, lo, mid - 1, key);
}

int lower_bound(const int a[], int n, int key) {
    int lo = 0, hi = n;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] < key) lo = mid + 1; else hi = mid;
    }
    return lo;
}
int count_in_range(const int a[], int n, int lo, int hi) {
    return lower_bound(a, n, hi + 1) - lower_bound(a, n, lo);
}

static int ev_cmp(const LogEvent *a, const LogEvent *b) {
    if (a->time != b->time) return a->time - b->time;
    if (a->host != b->host) return a->host - b->host;
    if (a->type != b->type) return a->type - b->type;
    return a->severity - b->severity;
}
static void merge_ev(LogEvent a[], LogEvent tmp[], int lo, int mid, int hi) {
    int i = lo, j = mid + 1, k = lo;
    while (i <= mid && j <= hi) tmp[k++] = (ev_cmp(&a[i], &a[j]) <= 0) ? a[i++] : a[j++];
    while (i <= mid) tmp[k++] = a[i++];
    while (j <= hi)  tmp[k++] = a[j++];
    for (k = lo; k <= hi; k++) a[k] = tmp[k];
}
static void msort_ev(LogEvent a[], LogEvent tmp[], int lo, int hi) {
    if (lo >= hi) return;
    int mid = (lo + hi) / 2;
    msort_ev(a, tmp, lo, mid);
    msort_ev(a, tmp, mid + 1, hi);
    merge_ev(a, tmp, lo, mid, hi);
}
void merge_sort_ev(LogEvent a[], int n) {
    if (n < 2) return;
    LogEvent *tmp = malloc(n * sizeof(LogEvent));
    msort_ev(a, tmp, 0, n - 1);
    free(tmp);
}
void quick_sort_ev(LogEvent a[], int lo, int hi) {
    if (lo >= hi) return;
    int mid = lo + (hi - lo) / 2;
    LogEvent t = a[mid]; a[mid] = a[hi]; a[hi] = t;
    LogEvent pivot = a[hi];
    int i = lo - 1;
    for (int j = lo; j < hi; j++)
        if (ev_cmp(&a[j], &pivot) < 0) { i++; t = a[i]; a[i] = a[j]; a[j] = t; }
    t = a[i + 1]; a[i + 1] = a[hi]; a[hi] = t;
    quick_sort_ev(a, lo, i);
    quick_sort_ev(a, i + 2, hi);
}
int ev_bsearch_iter(const LogEvent a[], int n, int time) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid].time == time) return mid;
        if (a[mid].time < time) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}
int ev_bsearch_rec(const LogEvent a[], int lo, int hi, int time) {
    if (lo > hi) return -1;
    int mid = lo + (hi - lo) / 2;
    if (a[mid].time == time) return mid;
    if (a[mid].time < time) return ev_bsearch_rec(a, mid + 1, hi, time);
    return ev_bsearch_rec(a, lo, mid - 1, time);
}
int ev_lower_bound(const LogEvent a[], int n, int time) {
    int lo = 0, hi = n;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid].time < time) lo = mid + 1; else hi = mid;
    }
    return lo;
}
int ev_count_in_range(const LogEvent a[], int n, int lo, int hi) {
    return ev_lower_bound(a, n, hi + 1) - ev_lower_bound(a, n, lo);
}

long max_subarray(const int a[], int lo, int hi) {
    if (lo == hi) return a[lo];
    int mid = (lo + hi) / 2;
    long left = max_subarray(a, lo, mid), right = max_subarray(a, mid + 1, hi);
    long sum = 0, bl = LONG_MIN, br = LONG_MIN;
    for (int i = mid; i >= lo; i--)     { sum += a[i]; if (sum > bl) bl = sum; }
    sum = 0;
    for (int i = mid + 1; i <= hi; i++) { sum += a[i]; if (sum > br) br = sum; }
    long best = bl + br;
    if (left > best)  best = left;
    if (right > best) best = right;
    return best;
}

long long power_mod(long long b, long long e, long long m) {
    if (e == 0) return 1 % m;
    long long half = power_mod(b, e / 2, m);
    long long r = half * half % m;
    if (e % 2) r = r * (b % m) % m;
    return r;
}

static int candidate(int lo, int hi, int k[][MAXV]) {
    if (lo == hi) return lo;
    int mid = (lo + hi) / 2;
    int a = candidate(lo, mid, k), b = candidate(mid + 1, hi, k);
    return k[a][b] ? b : a;
}
int find_celebrity(int n, int k[][MAXV]) {
    if (n <= 0) return -1;
    int c = candidate(0, n - 1, k);
    for (int i = 0; i < n; i++)
        if (i != c && (k[c][i] || !k[i][c])) return -1;
    return c;
}

void mat_classic(const int *A, const int *B, int *C, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            int s = 0;
            for (int k = 0; k < n; k++) s += A[i * n + k] * B[k * n + j];
            C[i * n + j] = s;
        }
}

#define CUTOFF 16

static void get(const int *M, int n, int r, int c, int *Q) {
    int h = n / 2;
    for (int i = 0; i < h; i++) for (int j = 0; j < h; j++) Q[i * h + j] = M[(i + r) * n + (j + c)];
}
static void put(int *M, int n, int r, int c, const int *Q) {
    int h = n / 2;
    for (int i = 0; i < h; i++) for (int j = 0; j < h; j++) M[(i + r) * n + (j + c)] = Q[i * h + j];
}
static void addm(const int *X, const int *Y, int *Z, int sz, int sign) {
    for (int i = 0; i < sz; i++) Z[i] = X[i] + sign * Y[i];
}

void mat_strassen(const int *A, const int *B, int *C, int n) {
    if (n <= CUTOFF) { mat_classic(A, B, C, n); return; }
    int h = n / 2, sz = h * h;
    int *m = malloc(sizeof(int) * sz * 19);
    int *A11 = m, *A12 = m + sz, *A21 = m + 2 * sz, *A22 = m + 3 * sz;
    int *B11 = m + 4 * sz, *B12 = m + 5 * sz, *B21 = m + 6 * sz, *B22 = m + 7 * sz;
    int *M1 = m + 8 * sz, *M2 = m + 9 * sz, *M3 = m + 10 * sz, *M4 = m + 11 * sz;
    int *M5 = m + 12 * sz, *M6 = m + 13 * sz, *M7 = m + 14 * sz;
    int *T1 = m + 15 * sz, *T2 = m + 16 * sz, *R = m + 17 * sz;

    get(A, n, 0, 0, A11); get(A, n, 0, h, A12); get(A, n, h, 0, A21); get(A, n, h, h, A22);
    get(B, n, 0, 0, B11); get(B, n, 0, h, B12); get(B, n, h, 0, B21); get(B, n, h, h, B22);

    addm(A11, A22, T1, sz, 1);  addm(B11, B22, T2, sz, 1);  mat_strassen(T1, T2, M1, h);
    addm(A21, A22, T1, sz, 1);                              mat_strassen(T1, B11, M2, h);
    addm(B12, B22, T2, sz, -1);                             mat_strassen(A11, T2, M3, h);
    addm(B21, B11, T2, sz, -1);                             mat_strassen(A22, T2, M4, h);
    addm(A11, A12, T1, sz, 1);                              mat_strassen(T1, B22, M5, h);
    addm(A21, A11, T1, sz, -1); addm(B11, B12, T2, sz, 1);  mat_strassen(T1, T2, M6, h);
    addm(A12, A22, T1, sz, -1); addm(B21, B22, T2, sz, 1);  mat_strassen(T1, T2, M7, h);

    for (int i = 0; i < sz; i++) R[i] = M1[i] + M4[i] - M5[i] + M7[i];
    put(C, n, 0, 0, R);
    for (int i = 0; i < sz; i++) R[i] = M3[i] + M5[i];
    put(C, n, 0, h, R);
    for (int i = 0; i < sz; i++) R[i] = M2[i] + M4[i];
    put(C, n, h, 0, R);
    for (int i = 0; i < sz; i++) R[i] = M1[i] - M2[i] + M3[i] + M6[i];
    put(C, n, h, h, R);
    free(m);
}

void graph_init(Graph *g, int n) {
    g->n = n;
    for (int i = 0; i < MAXV; i++)
        for (int j = 0; j < MAXV; j++) g->w[i][j] = (i == j) ? 0 : INF;
}
void graph_edge(Graph *g, int u, int v, int w)  { g->w[u][v] = w; }
void graph_edge2(Graph *g, int u, int v, int w) { g->w[u][v] = w; g->w[v][u] = w; }

static int *order_by(const int key[], int n) {
    int *idx = malloc((n > 0 ? n : 1) * sizeof(int));
    for (int i = 0; i < n; i++) idx[i] = i;
    for (int i = 1; i < n; i++) {
        int k = idx[i], j = i - 1;
        while (j >= 0 && key[idx[j]] > key[k]) { idx[j + 1] = idx[j]; j--; }
        idx[j + 1] = k;
    }
    return idx;
}

int activity_select(const int s[], const int f[], int n, int chosen[]) {
    int *idx = order_by(f, n), cnt = 0, last = INT_MIN;
    for (int i = 0; i < n; i++) {
        int x = idx[i];
        if (s[x] >= last) { chosen[cnt++] = x; last = f[x]; }
    }
    free(idx);
    return cnt;
}

int interval_partition(const int s[], const int f[], int n) {
    int *idx = order_by(s, n), *end = malloc((n > 0 ? n : 1) * sizeof(int)), rooms = 0;
    for (int i = 0; i < n; i++) {
        int x = idx[i], r;
        for (r = 0; r < rooms; r++) if (end[r] <= s[x]) break;
        if (r == rooms) rooms++;
        end[r] = f[x];
    }
    free(idx); free(end);
    return rooms;
}

typedef struct { int freq, left, right; } HNode;

static void walk(HNode t[], int i, char buf[], int depth, char codes[][HUF_LEN]) {
    if (t[i].left < 0) { buf[depth] = 0; strcpy(codes[i], buf); return; }
    buf[depth] = '0'; walk(t, t[i].left,  buf, depth + 1, codes);
    buf[depth] = '1'; walk(t, t[i].right, buf, depth + 1, codes);
}

int huffman(const int freq[], int n, char codes[][HUF_LEN]) {
    if (n < 1 || n > MAXSYM) return -1;
    if (n == 1) { strcpy(codes[0], "0"); return freq[0]; }
    HNode t[2 * MAXSYM]; int alive[2 * MAXSYM] = {0}, total = n;
    for (int i = 0; i < n; i++) { t[i].freq = freq[i]; t[i].left = t[i].right = -1; alive[i] = 1; }
    while (total < 2 * n - 1) {
        int a = -1, b = -1;
        for (int i = 0; i < total; i++) if (alive[i]) {
            if (a < 0 || t[i].freq < t[a].freq) { b = a; a = i; }
            else if (b < 0 || t[i].freq < t[b].freq) b = i;
        }
        t[total].freq = t[a].freq + t[b].freq; t[total].left = a; t[total].right = b;
        alive[a] = alive[b] = 0; alive[total++] = 1;
    }
    char buf[HUF_LEN];
    walk(t, total - 1, buf, 0, codes);
    int bits = 0;
    for (int i = 0; i < n; i++) bits += freq[i] * (int)strlen(codes[i]);
    return bits;
}

void dijkstra(const Graph *g, int src, int dist[], int prev[]) {
    int done[MAXV] = {0};
    for (int i = 0; i < g->n; i++) { dist[i] = INF; prev[i] = -1; }
    dist[src] = 0;
    for (int c = 0; c < g->n; c++) {
        int u = -1;
        for (int i = 0; i < g->n; i++) if (!done[i] && (u < 0 || dist[i] < dist[u])) u = i;
        if (dist[u] == INF) break;
        done[u] = 1;
        for (int v = 0; v < g->n; v++)
            if (!done[v] && g->w[u][v] < INF && dist[u] + g->w[u][v] < dist[v]) {
                dist[v] = dist[u] + g->w[u][v]; prev[v] = u;
            }
    }
}

int prim(const Graph *g) {
    int in[MAXV] = {0}, key[MAXV], total = 0;
    for (int i = 0; i < g->n; i++) key[i] = INF;
    key[0] = 0;
    for (int c = 0; c < g->n; c++) {
        int u = -1;
        for (int i = 0; i < g->n; i++) if (!in[i] && (u < 0 || key[i] < key[u])) u = i;
        if (key[u] == INF) return -1;
        in[u] = 1; total += key[u];
        for (int v = 0; v < g->n; v++) if (!in[v] && g->w[u][v] < key[v]) key[v] = g->w[u][v];
    }
    return total;
}

typedef struct { int u, v, w; } Edge;
static int find(int p[], int x) { return p[x] == x ? x : (p[x] = find(p, p[x])); }

int kruskal(const Graph *g) {
    Edge e[MAXV * MAXV]; int m = 0;
    for (int u = 0; u < g->n; u++)
        for (int v = u + 1; v < g->n; v++)
            if (g->w[u][v] < INF) { e[m].u = u; e[m].v = v; e[m].w = g->w[u][v]; m++; }
    for (int i = 1; i < m; i++) {
        Edge k = e[i]; int j = i - 1;
        while (j >= 0 && e[j].w > k.w) { e[j + 1] = e[j]; j--; }
        e[j + 1] = k;
    }
    int p[MAXV], total = 0, used = 0;
    for (int i = 0; i < g->n; i++) p[i] = i;
    for (int i = 0; i < m; i++) {
        int a = find(p, e[i].u), b = find(p, e[i].v);
        if (a != b) { p[a] = b; total += e[i].w; used++; }
    }
    return used == g->n - 1 ? total : -1;
}

static int max2(int a, int b) { return a > b ? a : b; }

void ratio_order(const int w[], const int v[], int n, int idx[]) {
    for (int i = 0; i < n; i++) idx[i] = i;
    for (int i = 1; i < n; i++) {
        int k = idx[i], j = i - 1;
        while (j >= 0 && (long)v[idx[j]] * w[k] < (long)v[k] * w[idx[j]]) { idx[j + 1] = idx[j]; j--; }
        idx[j + 1] = k;
    }
}

int knapsack_dp(const int w[], const int v[], int n, int W) {
    if (n < 0 || W < 0) return -1;
    int cols = W + 1;
    int *dp = calloc((size_t)(n + 1) * cols, sizeof(int));
    for (int i = 1; i <= n; i++)
        for (int c = 0; c <= W; c++) {
            dp[i * cols + c] = dp[(i - 1) * cols + c];
            if (w[i - 1] <= c)
                dp[i * cols + c] = max2(dp[i * cols + c], dp[(i - 1) * cols + c - w[i - 1]] + v[i - 1]);
        }
    int best = dp[n * cols + W];
    free(dp);
    return best;
}

int knapsack_greedy(const int w[], const int v[], int n, int W) {
    int *idx = malloc((n > 0 ? n : 1) * sizeof(int)), used = 0, val = 0;
    ratio_order(w, v, n, idx);
    for (int i = 0; i < n; i++) {
        int x = idx[i];
        if (used + w[x] <= W) { used += w[x]; val += v[x]; }
    }
    free(idx);
    return val;
}

static int mc_m[MAXN + 1][MAXN + 1], mc_s[MAXN + 1][MAXN + 1];

static void paren(int i, int j, char *out) {
    if (i == j) { sprintf(out + strlen(out), "A%d", i); return; }
    strcat(out, "(");
    paren(i, mc_s[i][j], out);
    strcat(out, " x ");
    paren(mc_s[i][j] + 1, j, out);
    strcat(out, ")");
}
int matrix_chain(const int p[], int n, char *out) {
    if (n < 1 || n > MAXN) return -1;
    for (int i = 1; i <= n; i++) mc_m[i][i] = 0;
    for (int len = 2; len <= n; len++)
        for (int i = 1; i + len - 1 <= n; i++) {
            int j = i + len - 1;
            mc_m[i][j] = INF;
            for (int k = i; k < j; k++) {
                int c = mc_m[i][k] + mc_m[k + 1][j] + p[i - 1] * p[k] * p[j];
                if (c < mc_m[i][j]) { mc_m[i][j] = c; mc_s[i][j] = k; }
            }
        }
    if (out) { out[0] = 0; paren(1, n, out); }
    return mc_m[1][n];
}

int lcs(const char *a, const char *b, char *out) {
    int n = (int)strlen(a), m = (int)strlen(b), cols = m + 1;
    int *L = calloc((size_t)(n + 1) * cols, sizeof(int));
    for (int i = 1; i <= n; i++)
        for (int j = 1; j <= m; j++)
            L[i * cols + j] = (a[i - 1] == b[j - 1]) ? L[(i - 1) * cols + j - 1] + 1
                                                      : max2(L[(i - 1) * cols + j], L[i * cols + j - 1]);
    int len = L[n * cols + m];
    if (out) {
        int i = n, j = m, k = len;
        out[len] = 0;
        while (i > 0 && j > 0) {
            if (a[i - 1] == b[j - 1]) { out[--k] = a[i - 1]; i--; j--; }
            else if (L[(i - 1) * cols + j] >= L[i * cols + j - 1]) i--;
            else j--;
        }
    }
    free(L);
    return len;
}

int optimal_bst(const int freq[], int n) {
    if (n < 1 || n > MAXN) return 0;
    static int c[MAXN + 1][MAXN + 1];
    memset(c, 0, sizeof c);
    for (int len = 1; len <= n; len++)
        for (int i = 0; i + len - 1 < n; i++) {
            int j = i + len - 1, sum = 0;
            for (int t = i; t <= j; t++) sum += freq[t];
            c[i][j] = INF;
            for (int r = i; r <= j; r++) {
                int cost = (r > i ? c[i][r - 1] : 0) + (r < j ? c[r + 1][j] : 0) + sum;
                if (cost < c[i][j]) c[i][j] = cost;
            }
        }
    return c[0][n - 1];
}

int bellman_ford(const Graph *g, int src, int dist[]) {
    for (int i = 0; i < g->n; i++) dist[i] = INF;
    dist[src] = 0;
    for (int pass = 1; pass < g->n; pass++)
        for (int u = 0; u < g->n; u++)
            for (int v = 0; v < g->n; v++)
                if (u != v && g->w[u][v] < INF && dist[u] < INF && dist[u] + g->w[u][v] < dist[v])
                    dist[v] = dist[u] + g->w[u][v];
    for (int u = 0; u < g->n; u++)
        for (int v = 0; v < g->n; v++)
            if (u != v && g->w[u][v] < INF && dist[u] < INF && dist[u] + g->w[u][v] < dist[v])
                return 1;
    return 0;
}

void floyd_warshall(const Graph *g, int d[][MAXV]) {
    for (int i = 0; i < g->n; i++) for (int j = 0; j < g->n; j++) d[i][j] = g->w[i][j];
    for (int k = 0; k < g->n; k++)
        for (int i = 0; i < g->n; i++)
            for (int j = 0; j < g->n; j++)
                if (d[i][k] < INF && d[k][j] < INF && d[i][k] + d[k][j] < d[i][j])
                    d[i][j] = d[i][k] + d[k][j];
}

int tsp_dp(const Graph *g) {
    int n = g->n;
    if (n < 2 || n > MAXV) return INF;
    static int dp[1 << MAXV][MAXV];
    int full = 1 << n;
    for (int m = 0; m < full; m++) for (int i = 0; i < n; i++) dp[m][i] = INF;
    dp[1][0] = 0;
    for (int mask = 1; mask < full; mask += 2)
        for (int last = 0; last < n; last++) {
            if (!((mask >> last) & 1) || dp[mask][last] >= INF) continue;
            for (int nx = 0; nx < n; nx++) {
                if ((mask >> nx) & 1 || g->w[last][nx] >= INF) continue;
                int nm = mask | (1 << nx), cand = dp[mask][last] + g->w[last][nx];
                if (cand < dp[nm][nx]) dp[nm][nx] = cand;
            }
        }
    int best = INF;
    for (int last = 1; last < n; last++)
        if (dp[full - 1][last] < INF && g->w[last][0] < INF && dp[full - 1][last] + g->w[last][0] < best)
            best = dp[full - 1][last] + g->w[last][0];
    return best;
}

static int dfs(int r[][MAXV], int n, int u, int t, int f, int seen[]) {
    if (u == t) return f;
    seen[u] = 1;
    for (int v = 0; v < n; v++)
        if (!seen[v] && r[u][v] > 0) {
            int d = dfs(r, n, v, t, f < r[u][v] ? f : r[u][v], seen);
            if (d > 0) { r[u][v] -= d; r[v][u] += d; return d; }
        }
    return 0;
}

int max_flow(int cap[][MAXV], int n, int s, int t) {
    int r[MAXV][MAXV], total = 0, f;
    for (int i = 0; i < MAXV; i++) for (int j = 0; j < MAXV; j++) r[i][j] = cap[i][j];
    do {
        int seen[MAXV] = {0};
        f = dfs(r, n, s, t, INF, seen);
        total += f;
    } while (f > 0);
    return total;
}

static int try_match(int adj[][MAXV], int R, int u, int seen[], int matchR[]) {
    for (int v = 0; v < R; v++)
        if (adj[u][v] && !seen[v]) {
            seen[v] = 1;
            if (matchR[v] < 0 || try_match(adj, R, matchR[v], seen, matchR)) { matchR[v] = u; return 1; }
        }
    return 0;
}
int bipartite_match(int adj[][MAXV], int L, int R, int matchR[]) {
    int count = 0;
    for (int v = 0; v < R; v++) matchR[v] = -1;
    for (int u = 0; u < L; u++) {
        int seen[MAXV] = {0};
        count += try_match(adj, R, u, seen, matchR);
    }
    return count;
}

long str_cmps = 0;

static long long gcd(long long a, long long b) { return b ? gcd(b, a % b) : a; }

static long long mod_inverse(long long a, long long m) {
    long long m0 = m, x0 = 0, x1 = 1;
    a %= m;
    while (a > 1) {
        long long q = a / m, t = m;
        m = a % m; a = t;
        t = x0; x0 = x1 - q * x0; x1 = t;
    }
    return x1 < 0 ? x1 + m0 : x1;
}
long long crt(const long long a[], const long long m[], int k, long long *M) {
    long long prod = 1, x = 0;
    for (int i = 0; i < k; i++) {
        if (m[i] < 2) return -1;
        for (int j = i + 1; j < k; j++) if (gcd(m[i], m[j]) != 1) return -1;
        prod *= m[i];
    }
    for (int i = 0; i < k; i++) {
        long long Mi = prod / m[i];
        x = (x + (a[i] % m[i]) * Mi % prod * mod_inverse(Mi % m[i], m[i])) % prod;
    }
    if (M) *M = prod;
    return x;
}

int naive_search(const char *t, const char *p) {
    int n = (int)strlen(t), m = (int)strlen(p), cnt = 0;
    if (m == 0) return 0;
    for (int i = 0; i + m <= n; i++) {
        int j = 0;
        while (j < m) { str_cmps++; if (t[i + j] != p[j]) break; j++; }
        if (j == m) cnt++;
    }
    return cnt;
}

int rk_search(const char *t, const char *p) {
    int n = (int)strlen(t), m = (int)strlen(p), cnt = 0;
    if (m == 0 || n < m) return 0;
    const long long B = 256, Q = 1000000007LL;
    long long hp = 0, ht = 0, pw = 1;
    for (int i = 0; i < m - 1; i++) pw = pw * B % Q;
    for (int i = 0; i < m; i++) {
        hp = (hp * B + (unsigned char)p[i]) % Q;
        ht = (ht * B + (unsigned char)t[i]) % Q;
    }
    for (int i = 0; i + m <= n; i++) {
        if (hp == ht && strncmp(t + i, p, m) == 0) cnt++;
        if (i + m < n)
            ht = ((ht - (unsigned char)t[i] * pw % Q + Q) % Q * B + (unsigned char)t[i + m]) % Q;
    }
    return cnt;
}

static void build_lps(const char *p, int m, int lps[]) {
    int k = 0;
    lps[0] = 0;
    for (int i = 1; i < m; i++) {
        while (k > 0 && p[i] != p[k]) k = lps[k - 1];
        if (p[i] == p[k]) k++;
        lps[i] = k;
    }
}

int fa_search(const char *t, const char *p) {
    int n = (int)strlen(t), m = (int)strlen(p), cnt = 0;
    if (m == 0) return 0;
    int *lps = malloc(m * sizeof(int)), *tf = malloc((size_t)(m + 1) * 256 * sizeof(int));
    build_lps(p, m, lps);
    for (int st = 0; st <= m; st++)
        for (int c = 0; c < 256; c++) {
            if (st < m && (unsigned char)p[st] == c) tf[st * 256 + c] = st + 1;
            else tf[st * 256 + c] = (st == 0) ? 0 : tf[lps[st - 1] * 256 + c];
        }
    for (int i = 0, st = 0; i < n; i++) {
        st = tf[st * 256 + (unsigned char)t[i]];
        if (st == m) cnt++;
    }
    free(lps); free(tf);
    return cnt;
}

int kmp_search(const char *t, const char *p) {
    int n = (int)strlen(t), m = (int)strlen(p), cnt = 0;
    if (m == 0) return 0;
    int *lps = malloc(m * sizeof(int));
    build_lps(p, m, lps);
    for (int i = 0, k = 0; i < n; i++) {
        while (k > 0 && t[i] != p[k]) { str_cmps++; k = lps[k - 1]; }
        str_cmps++;
        if (t[i] == p[k]) k++;
        if (k == m) { cnt++; k = lps[k - 1]; }
    }
    free(lps);
    return cnt;
}

static LogEvent events[MAXLOG];
static int nev = 0, rejected = 0;
static Alert alerts[MAXALERT];
static int nal = 0, dropped = 0, sig_hits[NSIGS];
typedef struct { int by_host[NHOSTS], by_type[NTYPES], by_sev[6]; } EventIndex;
static EventIndex ix;
static int item_w[NITEMS], item_v[NITEMS];

static uint32_t lcg_state = 1;
static int lcg(int mod) {
    lcg_state = lcg_state * 1103515245u + 12345u;
    return (int)((lcg_state >> 16) % (uint32_t)mod);
}
static int to_min(int hhmm) { return hhmm / 100 * 60 + hhmm % 100; }

static const char *event_reason(const LogEvent *e) {
    if (e->time < 0 || e->time > 2359 || e->time % 100 > 59) return "time is not a valid HHMM";
    if (e->host < 0 || e->host >= NHOSTS)                    return "unknown host";
    if (e->type < 0 || e->type >= NTYPES)                    return "unknown event type";
    if (e->severity < 1 || e->severity > 5)                  return "severity outside 1..5";
    return NULL;
}
static int event_valid(const LogEvent *e) { return event_reason(e) == NULL; }

static void set_severity(LogEvent *e) {
    switch (e->type) {
        case EV_LOGIN:   e->severity = 1; break;
        case EV_FAIL:    e->severity = 2 + lcg(2); break;
        case EV_SCAN:    e->severity = 3; break;
        case EV_MALWARE: e->severity = 4 + lcg(2); break;
        default:         e->severity = 5; break;
    }
}

static void fill_fields(LogEvent *e) {
    int r = lcg(100);
    e->host = lcg(NHOSTS);
    e->type = r < 40 ? EV_LOGIN : r < 65 ? EV_FAIL : r < 80 ? EV_SCAN : r < 92 ? EV_MALWARE : EV_EXFIL;
    set_severity(e);
}

static void plant(LogEvent *ev, int n, int host, int skip, const int *seq, int len) {
    int seen = 0, placed = 0;
    for (int i = 0; i < n && placed < len; i++) {
        if (ev[i].host != host) continue;
        if (seen++ < skip) continue;
        ev[i].type = seq[placed++];
        set_severity(&ev[i]);
    }
}
static void random_events(LogEvent *a, int n) {
    for (int i = 0; i < n; i++) {
        a[i].time = rand() % 24 * 100 + rand() % 60;
        a[i].host = rand() % NHOSTS;
        a[i].type = rand() % NTYPES;
        a[i].severity = 1 + rand() % 5;
    }
}
static void scramble(LogEvent *a, int n) {
    lcg_state = 99;
    for (int i = n - 1; i > 0; i--) { int j = lcg(i + 1); LogEvent t = a[i]; a[i] = a[j]; a[j] = t; }
}

static void build_index(void) {
    memset(&ix, 0, sizeof ix);
    for (int i = 0; i < nev; i++) { ix.by_host[events[i].host]++; ix.by_type[events[i].type]++; ix.by_sev[events[i].severity]++; }
}

static int host_sequence(int h, char *text, int *pos) {
    int len = 0;
    for (int i = 0; i < nev; i++)
        if (events[i].host == h) { text[len] = type_char[events[i].type]; pos[len++] = i; }
    text[len] = 0;
    return len;
}

static void add_alert(int time, int host, int type, int sev, int rule) {
    if (nal == MAXALERT) { dropped++; return; }
    alerts[nal].time = time; alerts[nal].host = host; alerts[nal].type = type;
    alerts[nal].severity = sev; alerts[nal].rule = rule;
    nal++;
}
static void build_alerts(void) {
    nal = 0; dropped = 0;
    for (int i = 0; i < nev; i++)
        if (events[i].severity >= ALERT_SEV)
            add_alert(events[i].time, events[i].host, events[i].type, events[i].severity, -1);
    char *text = malloc(nev + 1);
    int *p = malloc((nev + 1) * sizeof(int));
    for (int s = 0; s < NSIGS; s++) sig_hits[s] = 0;
    for (int h = 0; h < NHOSTS; h++) {
        host_sequence(h, text, p);
        for (int s = 0; s < NSIGS; s++) {
            int m = (int)strlen(sigs[s].pattern);
            for (const char *q = strstr(text, sigs[s].pattern); q; q = strstr(q + 1, sigs[s].pattern)) {
                int last = p[(q - text) + m - 1];
                sig_hits[s]++;
                add_alert(events[last].time, h, events[last].type, sigs[s].severity, s);
            }
        }
    }
    free(text); free(p);
}

static void build_items(void) {
    int risk[NHOSTS][2] = {{0}};
    for (int i = 0; i < nal; i++) {
        if (alerts[i].rule >= 0) continue;
        int kind = (alerts[i].type == EV_MALWARE) ? 0 : 1;
        risk[alerts[i].host][kind] += alerts[i].severity * hosts[alerts[i].host].criticality;
    }
    for (int h = 0; h < NHOSTS; h++) {
        item_w[2 * h] = hosts[h].patch_cost; item_v[2 * h] = risk[h][0];
        item_w[2 * h + 1] = hosts[h].dlp_cost; item_v[2 * h + 1] = risk[h][1];
    }
}
static int item_budget(void) {
    int total = 0;
    for (int i = 0; i < NITEMS; i++) total += item_w[i];
    return total / 2;
}

static void analyze(void) {
    merge_sort_ev(events, nev);
    build_index();
    build_alerts();
    build_items();
}

static void default_events(void) {
    static const int t[200] = {
        1730, 905, 1415, 2210, 130, 1415, 845, 1950, 710, 2359,
        1200, 1530, 1712, 2241, 2234, 1314, 1437, 851, 48, 544,
        1321, 809, 648, 1006, 224, 322, 1138, 851, 146, 1434,
        359, 1205, 1718, 2039, 1136, 645, 202, 2114, 905, 755,
        324, 829, 2053, 1110, 1122, 642, 844, 2141, 238, 2010,
        1746, 710, 1424, 859, 2044, 1714, 2120, 114, 151, 1025,
        804, 658, 1856, 2220, 641, 1525, 2029, 416, 415, 2335,
        1716, 2337, 1357, 1825, 1114, 432, 1505, 155, 309, 2010,
        2127, 1904, 1224, 1929, 1616, 1755, 43, 2307, 2156, 1748,
        849, 2021, 318, 1310, 1400, 2356, 2316, 1648, 532, 355,
        2019, 2032, 1912, 423, 534, 1658, 38, 1031, 7, 1156,
        915, 115, 1805, 246, 1552, 248, 1749, 408, 2130, 1710,
        833, 1927, 659, 1748, 2344, 645, 925, 2141, 1128, 1628,
        315, 704, 1001, 1835, 737, 700, 245, 2003, 704, 155,
        1004, 1615, 842, 1513, 1708, 2359, 1836, 1515, 1551, 1312,
        306, 2127, 1127, 1329, 2303, 2141, 2006, 125, 2321, 315,
        612, 1728, 427, 517, 1415, 228, 1706, 141, 1753, 5,
        710, 1331, 1513, 1257, 110, 1200, 1216, 1418, 1344, 2350,
        1742, 2231, 412, 913, 137, 2334, 147, 1003, 137, 1532,
        1610, 132, 254, 504, 1904, 2155, 725, 356, 1815, 1838
    };
    static const int kill_chain[] = {EV_SCAN, EV_MALWARE, EV_EXFIL};
    static const int brute_force[] = {EV_FAIL, EV_FAIL, EV_FAIL, EV_LOGIN};
    lcg_state = 2026;
    nev = 200; rejected = 0;
    for (int i = 0; i < nev; i++) { events[i].time = t[i]; fill_fields(&events[i]); }
    merge_sort_ev(events, nev);
    plant(events, nev, 3, 8, kill_chain, 3);
    plant(events, nev, 2, 5, brute_force, 4);
    analyze();
}

static int load_logs(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    int n = 0, bad = 0;
    lcg_state = 2026;
    while (n < MAXLOG && fgets(line, sizeof line, f)) {
        LogEvent e;
        int got = sscanf(line, "%d %d %d %d", &e.time, &e.host, &e.type, &e.severity);
        if (got == EOF) continue;
        if (got == 1) fill_fields(&e);
        else if (got != 4) { bad++; continue; }
        if (event_valid(&e)) events[n++] = e; else bad++;
    }
    fclose(f);
    if (n == 0) return 0;
    nev = n; rejected = bad;
    analyze();
    return 1;
}

double now_ms(void) { return 1000.0 * clock() / CLOCKS_PER_SEC; }

static FILE *csv;

static void row(const char *algo, const char *data, long n, double ms, long aux, long result) {
    printf("%-14s %-16s %8ld %10.3f %12ld %10ld\n", algo, data, n, ms, aux, result);
    fprintf(csv, "%s,%s,%ld,%.3f,%ld,%ld\n", algo, data, n, ms, aux, result);
}
static int is_sorted(const int *a, int n) {
    for (int i = 1; i < n; i++) if (a[i - 1] > a[i]) return 0;
    return 1;
}
static int ev_is_sorted(const LogEvent *a, int n) {
    for (int i = 1; i < n; i++) if (ev_cmp(&a[i - 1], &a[i]) > 0) return 0;
    return 1;
}

static void bench_sort(const char *label, int n, int sorted_input) {
    int *a = malloc(n * sizeof(int)), *b = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++) a[i] = sorted_input ? i : rand();
    memcpy(b, a, n * sizeof(int));
    double t = now_ms(); merge_sort(b, n);
    row("merge_sort", label, n, now_ms() - t, 4L * n, is_sorted(b, n));
    memcpy(b, a, n * sizeof(int));
    t = now_ms(); quick_sort(b, 0, n - 1);
    row("quick_sort", label, n, now_ms() - t, 0, is_sorted(b, n));
    free(a); free(b);
}

static void bench_sort_ev(int n) {
    LogEvent *a = malloc(n * sizeof(LogEvent)), *b = malloc(n * sizeof(LogEvent));
    random_events(a, n);
    memcpy(b, a, n * sizeof(LogEvent));
    double t = now_ms(); merge_sort_ev(b, n);
    row("merge_sort_ev", "events", n, now_ms() - t, (long)n * (long)sizeof(LogEvent), ev_is_sorted(b, n));
    memcpy(b, a, n * sizeof(LogEvent));
    t = now_ms(); quick_sort_ev(b, 0, n - 1);
    row("quick_sort_ev", "events", n, now_ms() - t, 0, ev_is_sorted(b, n));
    free(a); free(b);
}

static void bench_str(const char *label, const char *t, const char *p) {
    int m = (int)strlen(p);
    const char *name[] = {"naive", "rabin_karp", "automaton", "kmp"};
    int (*fn[])(const char *, const char *) = {naive_search, rk_search, fa_search, kmp_search};
    long aux[] = {0, 0, (long)(m + 1) * 256 * 4, (long)m * 4};
    for (int i = 0; i < 4; i++) {
        double t0 = now_ms();
        int c = fn[i](t, p);
        row(name[i], label, (long)strlen(t), now_ms() - t0, aux[i], c);
    }
}

static void bench_matrix(int n) {
    int *A = malloc(n * n * 4), *B = malloc(n * n * 4), *C1 = malloc(n * n * 4), *C2 = malloc(n * n * 4);
    for (int i = 0; i < n * n; i++) { A[i] = rand() % 10; B[i] = rand() % 10; }
    char lab[32]; sprintf(lab, "%dx%d", n, n);
    double t = now_ms(); mat_classic(A, B, C1, n);
    row("mat_classic", lab, n, now_ms() - t, 0, 1);
    t = now_ms(); mat_strassen(A, B, C2, n);
    double ms = now_ms() - t; long aux = 0;
    for (int s = n; s > 16; s /= 2) aux += 19L * (s / 2) * (s / 2) * 4;
    row("mat_strassen", lab, n, ms, aux, memcmp(C1, C2, n * n * 4) == 0);
    free(A); free(B); free(C1); free(C2);
}

static void bench_knap(void) {
    int n = 20, w[20], v[20], tw = 0, reps = 200;
    for (int i = 0; i < n; i++) { w[i] = 1 + rand() % 30; v[i] = 1 + rand() % 50; tw += w[i]; }
    int W = tw / 2, val = 0;
    double t = now_ms();
    for (int r = 0; r < reps; r++) val = knapsack_dp(w, v, n, W);
    row("knap_dp", "n=20", n, (now_ms() - t) / reps, (long)(n + 1) * (W + 1) * 4, val);
    int opt = val;
    t = now_ms();
    for (int r = 0; r < reps; r++) val = knapsack_greedy(w, v, n, W);
    row("knap_greedy", "n=20", n, (now_ms() - t) / reps, 0, val);
    printf("   greedy quality = %d / %d of optimal value\n", val, opt);

}

void run_benchmarks(void) {
    csv = fopen("results.csv", "w");
    if (!csv) { printf("cannot write results.csv\n"); return; }
    fprintf(csv, "algorithm,dataset,n,time_ms,aux_bytes,result\n");
    printf("%-14s %-16s %8s %10s %12s %10s\n", "algorithm", "dataset", "n", "time_ms", "aux_bytes", "result");
    srand(42);
    bench_sort("small",       1000,   0);
    bench_sort("medium",      10000,  0);
    bench_sort("large",       100000, 0);
    bench_sort("adversarial", 20000,  1);
    bench_sort_ev(100000);

    int n = 1000000;
    char *t = malloc(n + 1), p[513];
    for (int i = 0; i < n; i++) t[i] = 'a' + rand() % 4;
    t[n] = 0;
    memcpy(p, t + 5000, 8); p[8] = 0;
    bench_str("random-1M", t, p);
    int m2 = 300000;
    memset(t, 'a', m2); t[m2] = 0;
    memset(p, 'a', 300); p[300] = 'b'; p[301] = 0;
    bench_str("adversarial", t, p);
    free(t);

    for (int s = 32; s <= 256; s *= 2) bench_matrix(s);
    bench_knap();
    fclose(csv);
    printf("\nwritten: results.csv\n");
}

static int passed = 0, failed = 0;
#define CHECK(c) do { if (c) passed++; else { failed++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static int cmp_ev(const void *a, const void *b) { return ev_cmp((const LogEvent *)a, (const LogEvent *)b); }

static void test_sorting(void) {
    int sizes[] = {0, 1, 2, 7, 50, 500};
    for (int s = 0; s < 6; s++) {
        int n = sizes[s], a[500], b[500], c[500];
        for (int i = 0; i < n; i++) a[i] = rand() % 20;
        memcpy(b, a, n * sizeof(int)); memcpy(c, a, n * sizeof(int));
        merge_sort(b, n); quick_sort(c, 0, n - 1); qsort(a, n, sizeof(int), cmp_int);
        CHECK(memcmp(a, b, n * sizeof(int)) == 0);
        CHECK(memcmp(a, c, n * sizeof(int)) == 0);
    }
    int v[] = {10, 20, 30, 40, 50};
    CHECK(bsearch_iter(v, 5, 30) == 2 && bsearch_rec(v, 0, 4, 30) == 2);
    CHECK(bsearch_iter(v, 5, 10) == 0 && bsearch_iter(v, 5, 50) == 4);
    CHECK(bsearch_iter(v, 5, 35) == -1 && bsearch_rec(v, 0, 4, 35) == -1);
    CHECK(bsearch_iter(v, 0, 10) == -1);
    CHECK(count_in_range(v, 5, 20, 40) == 3 && count_in_range(v, 5, 41, 49) == 0);
    CHECK(count_in_range(v, 5, 0, 100) == 5);
}

static void test_dnc(void) {
    int a[] = {-2, 1, -3, 4, -1, 2, 1, -5, 4}, neg[] = {-3, -1, -2};
    CHECK(max_subarray(a, 0, 8) == 6);
    CHECK(max_subarray(neg, 0, 2) == -1);
    CHECK(power_mod(2, 10, 1000) == 24 && power_mod(5, 0, 7) == 1);
    CHECK(power_mod(5, 6, 23) == 8 && power_mod(5, 15, 23) == 19);
    int k[MAXV][MAXV] = {{0}};
    k[0][1] = 1; k[0][2] = 1; k[1][2] = 1; k[3][0] = 1; k[3][1] = 1; k[3][2] = 1;
    CHECK(find_celebrity(4, k) == 2);
    k[2][0] = 1;
    CHECK(find_celebrity(4, k) == -1);
    int one[MAXV][MAXV] = {{0}};
    CHECK(find_celebrity(1, one) == 0 && find_celebrity(0, one) == -1);
    for (int n = 16; n <= 64; n *= 2) {
        int *A = malloc(n * n * 4), *B = malloc(n * n * 4), *C1 = malloc(n * n * 4), *C2 = malloc(n * n * 4);
        for (int i = 0; i < n * n; i++) { A[i] = rand() % 10 - 5; B[i] = rand() % 10 - 5; }
        mat_classic(A, B, C1, n); mat_strassen(A, B, C2, n);
        CHECK(memcmp(C1, C2, n * n * 4) == 0);
        free(A); free(B); free(C1); free(C2);
    }
}

static void test_greedy(void) {
    int s[] = {1, 3, 0, 5, 3, 5, 6, 8, 8, 2, 12}, f[] = {4, 5, 6, 7, 9, 9, 10, 11, 12, 14, 16}, ch[11];
    CHECK(activity_select(s, f, 11, ch) == 4);
    CHECK(activity_select(s, f, 0, ch) == 0);
    int s2[] = {1, 2, 3, 4}, f2[] = {5, 6, 7, 8}, s3[] = {1, 5}, f3[] = {4, 9};
    CHECK(interval_partition(s2, f2, 4) == 4 && interval_partition(s3, f3, 2) == 1);
    int fr[] = {5, 9, 12, 13, 16, 45}; char codes[MAXSYM][HUF_LEN];
    CHECK(huffman(fr, 6, codes) == 224);
    CHECK(strlen(codes[5]) == 1);
    CHECK(huffman(fr, 0, codes) == -1);

    Graph g; graph_init(&g, 3);
    graph_edge2(&g, 0, 1, 2); graph_edge2(&g, 1, 2, 3); graph_edge2(&g, 0, 2, 10);
    int d[MAXV], p[MAXV];
    dijkstra(&g, 0, d, p);
    CHECK(d[2] == 5 && p[2] == 1);
    CHECK(prim(&g) == 5 && kruskal(&g) == 5);
    Graph h; graph_init(&h, 4);
    graph_edge2(&h, 0, 1, 1); graph_edge2(&h, 2, 3, 1);
    CHECK(prim(&h) == -1 && kruskal(&h) == -1);
}

static void test_dp(void) {
    int w[] = {1, 3, 4, 5}, v[] = {1, 4, 5, 7};
    CHECK(knapsack_dp(w, v, 4, 7) == 9);
    CHECK(knapsack_dp(w, v, 4, 0) == 0 && knapsack_dp(w, v, 0, 5) == 0);
    CHECK(knapsack_dp(w, v, 4, -1) == -1);
    for (int t = 0; t < 30; t++) {
        int n = 1 + rand() % 12, ww[12], vv[12], W = 5 + rand() % 40, best = 0;
        for (int i = 0; i < n; i++) { ww[i] = 1 + rand() % 15; vv[i] = 1 + rand() % 30; }
        for (int m = 0; m < (1 << n); m++) {
            int sw = 0, sv = 0;
            for (int i = 0; i < n; i++) if (m >> i & 1) { sw += ww[i]; sv += vv[i]; }
            if (sw <= W && sv > best) best = sv;
        }
        CHECK(knapsack_dp(ww, vv, n, W) == best);
        CHECK(knapsack_greedy(ww, vv, n, W) <= best);
    }
    char buf[100];
    int p1[] = {10, 30, 5, 60}, p2[] = {30, 35, 15, 5, 10, 20, 25};
    CHECK(matrix_chain(p1, 3, buf) == 4500);
    CHECK(matrix_chain(p2, 6, buf) == 15125);
    CHECK(matrix_chain(p2, 0, buf) == -1);
    char out[20];
    CHECK(lcs("ABCBDAB", "BDCABA", out) == 4 && strlen(out) == 4);
    CHECK(lcs("", "ABC", out) == 0 && lcs("ABC", "XYZ", out) == 0 && lcs("ABC", "ABC", out) == 3);
    int fr[] = {34, 8, 50};
    CHECK(optimal_bst(fr, 3) == 142);

    Graph g; graph_init(&g, 3);
    graph_edge(&g, 0, 1, 4); graph_edge(&g, 0, 2, 5); graph_edge(&g, 2, 1, -3);
    int dist[MAXV], fw[MAXV][MAXV];
    CHECK(bellman_ford(&g, 0, dist) == 0 && dist[1] == 2);
    floyd_warshall(&g, fw);
    CHECK(fw[0][1] == 2 && fw[1][0] == INF);
    Graph c; graph_init(&c, 3);
    graph_edge(&c, 0, 1, 1); graph_edge(&c, 1, 2, -3); graph_edge(&c, 2, 0, 1);
    CHECK(bellman_ford(&c, 0, dist) == 1);

    Graph t; graph_init(&t, 4);
    graph_edge2(&t, 0, 1, 10); graph_edge2(&t, 0, 2, 15); graph_edge2(&t, 0, 3, 20);
    graph_edge2(&t, 1, 2, 35); graph_edge2(&t, 1, 3, 25); graph_edge2(&t, 2, 3, 30);
    CHECK(tsp_dp(&t) == 80);
    Graph z; graph_init(&z, 3); graph_edge(&z, 0, 1, 1);
    CHECK(tsp_dp(&z) == INF);
}

static void test_flow(void) {
    int cap[MAXV][MAXV] = {{0}};
    cap[0][1] = 16; cap[0][2] = 13; cap[1][2] = 10; cap[2][1] = 4; cap[1][3] = 12;
    cap[3][2] = 9; cap[2][4] = 14; cap[4][3] = 7; cap[3][5] = 20; cap[4][5] = 4;
    CHECK(max_flow(cap, 6, 0, 5) == 23);
    CHECK(max_flow(cap, 6, 5, 0) == 0);
    int adj[MAXV][MAXV] = {{0}}, mr[MAXV];
    adj[0][0] = adj[0][1] = adj[1][0] = adj[2][1] = adj[2][2] = 1;
    CHECK(bipartite_match(adj, 3, 3, mr) == 3);
    int adj2[MAXV][MAXV] = {{0}};
    adj2[0][0] = adj2[1][0] = 1;
    CHECK(bipartite_match(adj2, 2, 2, mr) == 1);
}

static void test_strings(void) {
    long long a[] = {2, 3, 2}, m[] = {3, 5, 7}, bad[] = {4, 6}, M;
    CHECK(crt(a, m, 3, &M) == 23 && M == 105);
    CHECK(crt(a, bad, 2, &M) == -1);
    struct { const char *t, *p; int want; } cases[] = {
        {"abababab", "aba", 3}, {"aaaa", "aa", 3}, {"hello world", "xyz", 0},
        {"abc", "abcd", 0}, {"abc", "abc", 1}, {"", "a", 0}, {"abc", "", 0},
        {"mississippi", "issi", 2}, {"aaaaaaaaab", "aaab", 1},
    };
    for (int i = 0; i < 9; i++) {
        CHECK(naive_search(cases[i].t, cases[i].p) == cases[i].want);
        CHECK(rk_search(cases[i].t, cases[i].p) == cases[i].want);
        CHECK(fa_search(cases[i].t, cases[i].p) == cases[i].want);
        CHECK(kmp_search(cases[i].t, cases[i].p) == cases[i].want);
    }
}

static void test_records(void) {
    LogEvent *save = malloc((nev > 0 ? nev : 1) * sizeof(LogEvent));
    memcpy(save, events, nev * sizeof(LogEvent));
    int snev = nev, srej = rejected;

    LogEvent ok = {930, 1, 2, 3}, b1 = {2475, 1, 2, 3}, b2 = {960, 1, 2, 3}, b3 = {-5, 1, 2, 3};
    LogEvent b4 = {930, 6, 2, 3}, b5 = {930, -1, 2, 3}, b6 = {930, 1, 5, 3}, b7 = {930, 1, 2, 0}, b8 = {930, 1, 2, 6};
    LogEvent edge1 = {0, 0, 0, 1}, edge2 = {2359, NHOSTS - 1, NTYPES - 1, 5};
    CHECK(event_valid(&ok) && event_valid(&edge1) && event_valid(&edge2));
    CHECK(!event_valid(&b1) && !event_valid(&b2) && !event_valid(&b3));
    CHECK(!event_valid(&b4) && !event_valid(&b5) && !event_valid(&b6));
    CHECK(!event_valid(&b7) && !event_valid(&b8));

    srand(5);
    int sizes[] = {0, 1, 2, 7, 50, 500};
    for (int s = 0; s < 6; s++) {
        int n = sizes[s];
        LogEvent *a = malloc((n + 1) * sizeof(LogEvent)), *b = malloc((n + 1) * sizeof(LogEvent)), *c = malloc((n + 1) * sizeof(LogEvent));
        random_events(a, n);
        for (int i = 0; i < n; i++) { a[i].time = a[i].time / 600 * 100 + 30; a[i].host %= 2; }
        memcpy(b, a, n * sizeof(LogEvent)); memcpy(c, a, n * sizeof(LogEvent));
        merge_sort_ev(b, n); quick_sort_ev(c, 0, n - 1); qsort(a, n, sizeof(LogEvent), cmp_ev);
        CHECK(memcmp(a, b, n * sizeof(LogEvent)) == 0);
        CHECK(memcmp(a, c, n * sizeof(LogEvent)) == 0);
        free(a); free(b); free(c);
    }

    default_events();
    CHECK(nev == 200 && rejected == 0);
    int all_valid = 1, sorted = 1, hs = 0, ts = 0, ss_ = 0;
    for (int i = 0; i < nev; i++) {
        if (!event_valid(&events[i])) all_valid = 0;
        if (i > 0 && events[i - 1].time > events[i].time) sorted = 0;
    }
    for (int h = 0; h < NHOSTS; h++) hs += ix.by_host[h];
    for (int t = 0; t < NTYPES; t++) ts += ix.by_type[t];
    for (int s = 1; s <= 5; s++) ss_ += ix.by_sev[s];
    CHECK(all_valid && sorted);
    CHECK(hs == nev && ts == nev && ss_ == nev);

    int found_ok = 1;
    for (int i = 0; i < nev; i += 7) {
        int key = events[i].time, a1 = ev_bsearch_iter(events, nev, key), a2 = ev_bsearch_rec(events, 0, nev - 1, key);
        if (a1 < 0 || events[a1].time != key || a1 != a2) found_ok = 0;
    }
    CHECK(found_ok);
    CHECK(ev_bsearch_iter(events, nev, 2475) == -1 && ev_bsearch_rec(events, 0, nev - 1, 2475) == -1);
    int brute = 0;
    for (int i = 0; i < nev; i++) if (events[i].time >= 900 && events[i].time <= 1700) brute++;
    CHECK(ev_count_in_range(events, nev, 900, 1700) == brute);
    CHECK(ev_count_in_range(events, nev, 0, 2359) == nev && ev_count_in_range(events, nev, 2360, 2400) == 0);

    int sev_alerts = 0, high = 0, pat_alerts = 0, hits = 0;
    for (int i = 0; i < nal; i++) { if (alerts[i].rule < 0) sev_alerts++; else pat_alerts++; }
    for (int i = 0; i < nev; i++) if (events[i].severity >= ALERT_SEV) high++;
    for (int s = 0; s < NSIGS; s++) hits += sig_hits[s];
    CHECK(sev_alerts == high && pat_alerts == hits && dropped == 0);
    CHECK(sig_hits[3] >= 1);

    char *text = malloc(nev + 1); int *pp = malloc((nev + 1) * sizeof(int));
    int agree = 1;
    for (int s = 0; s < NSIGS; s++) {
        int tn = 0, tr = 0, tf = 0, tk = 0;
        for (int h = 0; h < NHOSTS; h++) {
            host_sequence(h, text, pp);
            tn += naive_search(text, sigs[s].pattern); tr += rk_search(text, sigs[s].pattern);
            tf += fa_search(text, sigs[s].pattern);    tk += kmp_search(text, sigs[s].pattern);
        }
        if (tn != sig_hits[s] || tr != sig_hits[s] || tf != sig_hits[s] || tk != sig_hits[s]) agree = 0;
    }
    CHECK(agree);
    free(text); free(pp);

    char codes[MAXSYM][HUF_LEN];
    int bits = huffman(ix.by_type, NTYPES, codes);
    CHECK(bits > 0 && bits <= 3 * nev);

    int W = item_budget(), best = 0;
    for (int m = 0; m < (1 << NITEMS); m++) {
        int sw = 0, sv = 0;
        for (int i = 0; i < NITEMS; i++) if (m >> i & 1) { sw += item_w[i]; sv += item_v[i]; }
        if (sw <= W && sv > best) best = sv;
    }
    CHECK(knapsack_dp(item_w, item_v, NITEMS, W) == best);
    CHECK(knapsack_greedy(item_w, item_v, NITEMS, W) <= best);

    memcpy(events, save, snev * sizeof(LogEvent));
    nev = snev; rejected = srej;
    analyze();
    free(save);
}

int run_tests(void) {
    srand(7);
    test_sorting(); test_dnc(); test_greedy(); test_dp();
    test_flow(); test_strings(); test_records();
    printf("tests passed: %d, failed: %d\n", passed, failed);
    return failed ? 1 : 0;
}

static void print_event(const LogEvent *e) {
    printf("%04d  %-9s %-12s severity %d\n", e->time, hosts[e->host].name, type_name[e->type], e->severity);
}

static void build_network(Graph *g) {
    graph_init(g, 6);
    graph_edge2(g, 0, 1, 4); graph_edge2(g, 0, 2, 2); graph_edge2(g, 1, 2, 1);
    graph_edge2(g, 1, 3, 5); graph_edge2(g, 2, 3, 8); graph_edge2(g, 2, 4, 10);
    graph_edge2(g, 3, 4, 2); graph_edge2(g, 3, 5, 6); graph_edge2(g, 4, 5, 3);
}
static void print_path(const int prev[], int v) {
    if (v < 0) return;
    print_path(prev, prev[v]);
    printf(prev[v] < 0 ? "%s" : " -> %s", hosts[v].name);
}

static void build_flow(int cap[][MAXV]) {
    memset(cap, 0, sizeof(int) * MAXV * MAXV);
    cap[0][1] = 16; cap[0][2] = 13; cap[1][2] = 10; cap[2][1] = 4; cap[1][3] = 12;
    cap[3][2] = 9; cap[2][4] = 14; cap[4][3] = 7; cap[3][5] = 20; cap[4][5] = 4;
}

static void show_plan(int W) {
    int best = -1, bm = 0;
    for (int m = 0; m < (1 << NITEMS); m++) {
        int sw = 0, sv = 0;
        for (int i = 0; i < NITEMS; i++) if (m >> i & 1) { sw += item_w[i]; sv += item_v[i]; }
        if (sw <= W && sv > best) { best = sv; bm = m; }
    }
    for (int i = 0; i < NITEMS; i++)
        if (bm >> i & 1)
            printf("   %-5s %-9s cost %2d h, risk removed %d\n", i % 2 ? "DLP" : "patch", hosts[i / 2].name, item_w[i], item_v[i]);
}

static void show_kpis(void) {
    int hour_alerts[24] = {0}, crit = 0, sev_alerts = 0, busiest = 0, peak = 0, total_v = 0;
    for (int i = 0; i < nal; i++)
        if (alerts[i].rule < 0) {
            hour_alerts[alerts[i].time / 100]++; sev_alerts++;
            if (alerts[i].severity == 5) crit++;
        }
    for (int h = 1; h < NHOSTS; h++) if (ix.by_host[h] > ix.by_host[busiest]) busiest = h;
    for (int h = 1; h < 24; h++) if (hour_alerts[h] > hour_alerts[peak]) peak = h;
    for (int i = 0; i < NITEMS; i++) total_v += item_v[i];
    int W = item_budget(), covered = knapsack_dp(item_w, item_v, NITEMS, W);
    printf("service indicators:\n");
    printf("   events accepted / rejected     : %d / %d  (acceptance %.1f%%)\n", nev, rejected, 100.0 * nev / (nev + rejected));
    printf("   high-severity alerts           : %d  (%d critical, %.2f per hour)\n", sev_alerts, crit, sev_alerts / 24.0);
    printf("   correlated incidents (patterns): %d\n", nal - sev_alerts);
    printf("   busiest host                   : %s with %d events (%.1f%% of all)\n", hosts[busiest].name, ix.by_host[busiest], 100.0 * ix.by_host[busiest] / nev);
    printf("   peak alert hour                : %02d:00 with %d alerts\n", peak, hour_alerts[peak]);
    printf("   risk coverage at budget %d h    : %d of %d (%.1f%%)\n", W, covered, total_v, total_v ? 100.0 * covered / total_v : 100.0);
    if (dropped) printf("   WARNING: %d alerts did not fit (limit %d)\n", dropped, MAXALERT);
}

static void demo_validation(void) {
    printf("validation rules: time is a real HHMM (hour 0-23, minute 0-59); host 0-%d; type 0-%d; severity 1-5\n\n", NHOSTS - 1, NTYPES - 1);
    LogEvent batch[] = {{930, 1, 2, 3}, {2475, 1, 2, 3}, {1200, 9, 1, 2}, {1500, 2, 7, 1},
                        {800, 0, 0, 0}, {960, 3, 1, 2}, {2359, 5, 4, 5}, {-15, 0, 0, 1}};
    int acc = 0, rej = 0;
    for (int i = 0; i < 8; i++) {
        const char *why = event_reason(&batch[i]);
        printf("   time %5d host %2d type %2d sev %2d  ->  %s%s%s\n", batch[i].time, batch[i].host, batch[i].type, batch[i].severity,
               why ? "REJECT (" : "ACCEPT", why ? why : "", why ? ")" : "");
        if (why) rej++; else acc++;
    }
    printf("test batch: %d accepted, %d rejected\n\n", acc, rej);
    printf("current dataset (%d events):\n", nev);
    show_kpis();
}

static void demo_sorting(void) {
    LogEvent *a = malloc(nev * sizeof(LogEvent)), *b = malloc(nev * sizeof(LogEvent));
    memcpy(a, events, nev * sizeof(LogEvent));
    scramble(a, nev);
    memcpy(b, a, nev * sizeof(LogEvent));
    printf("%d event records.  Arrival order (first 3):\n", nev);
    for (int i = 0; i < 3 && i < nev; i++) { printf("   "); print_event(&a[i]); }
    merge_sort_ev(a, nev); quick_sort_ev(b, 0, nev - 1);
    printf("after sorting by time (first 3):\n");
    for (int i = 0; i < 3 && i < nev; i++) { printf("   "); print_event(&a[i]); }
    printf("merge and quick sort agree : %s\n", memcmp(a, b, nev * sizeof(LogEvent)) == 0 ? "yes" : "NO");
    int key = a[nev / 2].time;
    printf("search time %04d : iterative index %d, recursive index %d\n", key,
           ev_bsearch_iter(a, nev, key), ev_bsearch_rec(a, 0, nev - 1, key));
    printf("search time 2475 : index %d (not a real time)\n", ev_bsearch_iter(a, nev, 2475));
    printf("time index         : %d events between 0900 and 1700\n", ev_count_in_range(a, nev, 900, 1700));
    printf("host index (events per host):\n");
    for (int h = 0; h < NHOSTS; h++) printf("   %-9s %d\n", hosts[h].name, ix.by_host[h]);
    printf("severity index     :");
    for (int s = 1; s <= 5; s++) printf(" sev%d=%d", s, ix.by_sev[s]);
    printf("\n");
    free(a); free(b);
}

static void demo_dnc(void) {
    int risk[24] = {0};
    for (int i = 0; i < nev; i++) risk[events[i].time / 100] += events[i].severity - 2;
    printf("hourly risk change:");
    for (int h = 0; h < 24; h++) printf(" %d", risk[h]);
    printf("\nworst stretch of hours (max subarray): %ld\n", max_subarray(risk, 0, 23));
    long long A = power_mod(5, 6, 23), B = power_mod(5, 15, 23);
    printf("log shipping key exchange (Diffie-Hellman p=23 g=5): public %lld and %lld, shared secret %lld = %lld\n",
           A, B, power_mod(B, 6, 23), power_mod(A, 15, 23));
    int k[MAXV][MAXV] = {{0}};
    for (int h = 0; h < NHOSTS; h++) if (h != 4) k[h][4] = 1;
    int c = find_celebrity(NHOSTS, k);
    printf("log collector (celebrity) among %d hosts: %s\n", NHOSTS, c >= 0 ? hosts[c].name : "none");
    int n = 128, *X = malloc(n * n * 4), *Y = malloc(n * n * 4), *C1 = malloc(n * n * 4), *C2 = malloc(n * n * 4);
    for (int i = 0; i < n * n; i++) { X[i] = rand() % 10; Y[i] = rand() % 10; }
    double t = now_ms(); mat_classic(X, Y, C1, n); double t1 = now_ms() - t;
    t = now_ms(); mat_strassen(X, Y, C2, n); double t2 = now_ms() - t;
    printf("128x128 matrix product: classical %.2f ms, Strassen %.2f ms, same answer: %s\n",
           t1, t2, memcmp(C1, C2, n * n * 4) == 0 ? "yes" : "NO");
    free(X); free(Y); free(C1); free(C2);
}

static void demo_greedy(void) {
    int s[SCHED_MAX], f[SCHED_MAX], ch[SCHED_MAX], n = 0;
    for (int i = 0; i < nal && n < SCHED_MAX; i++)
        if (alerts[i].rule < 0) { s[n] = to_min(alerts[i].time); f[n] = s[n] + 15 * alerts[i].severity; n++; }
    int c = activity_select(s, f, n, ch);
    printf("investigation jobs (15 min x severity each): %d\n", n);
    printf("one analyst can run %d of them (start times:", c);
    for (int i = 0; i < c && i < 8; i++) printf(" %02d:%02d", s[ch[i]] / 60, s[ch[i]] % 60);
    printf("%s)\nanalysts needed to run all %d at once: %d\n", c > 8 ? " ..." : "", n, interval_partition(s, f, n));

    char codes[MAXSYM][HUF_LEN];
    int bits = huffman(ix.by_type, NTYPES, codes);
    printf("Huffman for event types (%d events): %d bits vs %d fixed-length\n", nev, bits, 3 * nev);
    for (int t = 0; t < NTYPES; t++) printf("   %-12s count %3d code %s\n", type_name[t], ix.by_type[t], codes[t]);

    Graph g; build_network(&g);
    int d[MAXV], p[MAXV];
    dijkstra(&g, 0, d, p);
    printf("easiest attack path internet-facing gateway -> database: effort %d, path ", d[3]);
    print_path(p, 3);
    printf("\neasiest attack path gateway -> backup: effort %d, path ", d[5]);
    print_path(p, 5);
    printf("\ncheapest cabling that links everything: Prim %d, Kruskal %d\n", prim(&g), kruskal(&g));
}

static void demo_dp(void) {
    int W = item_budget(), tc = 0;
    for (int i = 0; i < NITEMS; i++) tc += item_w[i];
    printf("containment actions: %d (a patch and a DLP rule per host), total cost %d h, budget %d h\n", NITEMS, tc, W);
    printf("   best risk removed: DP %d (greedy gets %d).  Chosen plan:\n", knapsack_dp(item_w, item_v, NITEMS, W), knapsack_greedy(item_w, item_v, NITEMS, W));
    show_plan(W);
    int p[] = {30, 35, 15, 5, 10, 20, 25}; char buf[100];
    printf("matrix chain: %d multiplications, order %s\n", matrix_chain(p, 6, buf), buf);
    char out[20];
    printf("LCS of attack traces ABCBDAB / BDCABA: length %d (%s)\n", lcs("ABCBDAB", "BDCABA", out), out);
    printf("optimal BST over the %d hosts, searched as often as they appear in the logs: cost %d\n", NHOSTS, optimal_bst(ix.by_host, NHOSTS));
    Graph g; graph_init(&g, 3);
    graph_edge(&g, 0, 1, 4); graph_edge(&g, 0, 2, 5); graph_edge(&g, 2, 1, -3);
    int dist[MAXV], fw[MAXV][MAXV];
    int neg = bellman_ford(&g, 0, dist);
    printf("Bellman-Ford with a negative edge: dist to 1 = %d, negative cycle: %s\n", dist[1], neg ? "yes" : "no");
    floyd_warshall(&g, fw);
    printf("Floyd-Warshall says dist 0 -> 1 = %d\n", fw[0][1]);
    Graph t; graph_init(&t, 4);
    graph_edge2(&t, 0, 1, 10); graph_edge2(&t, 0, 2, 15); graph_edge2(&t, 0, 3, 20);
    graph_edge2(&t, 1, 2, 35); graph_edge2(&t, 1, 3, 25); graph_edge2(&t, 2, 3, 30);
    printf("shortest patrol tour over 4 sites (TSP): %d\n", tsp_dp(&t));
}

static void demo_flow(void) {
    int cap[MAXV][MAXV];
    build_flow(cap);
    printf("max traffic internet -> backup: %d Mbps\n", max_flow(cap, 6, 0, 5));
    int adj[MAXV][MAXV] = {{0}}, mr[MAXV];
    adj[0][0] = adj[0][1] = adj[1][0] = adj[2][1] = adj[2][2] = 1;
    int m = bipartite_match(adj, 3, 3, mr);
    printf("analysts matched to incident types: %d of 3\n", m);
    for (int j = 0; j < 3; j++) if (mr[j] >= 0) printf("   incident %d -> analyst %d\n", j, mr[j]);
}

static void demo_strings(void) {
    long long a[] = {2, 3, 2}, m[] = {3, 5, 7}, M;
    long long x = crt(a, m, 3, &M);
    printf("CRT: three alerts fire every 3, 5, 7 days (offsets 2,3,2): all coincide on day %lld, repeating every %lld days\n", x, M);

    printf("\nevent sequences: each host's events as letters (L login-ok, F login-fail, S scan, M malware, X exfiltration)\n");
    char *text = malloc(nev + 1); int *pp = malloc((nev + 1) * sizeof(int));
    for (int s = 0; s < NSIGS; s++) {
        int tot[4] = {0}; long cn = 0, ck = 0;
        for (int h = 0; h < NHOSTS; h++) {
            host_sequence(h, text, pp);
            str_cmps = 0; tot[0] += naive_search(text, sigs[s].pattern); cn += str_cmps;
            tot[1] += rk_search(text, sigs[s].pattern);
            tot[2] += fa_search(text, sigs[s].pattern);
            str_cmps = 0; tot[3] += kmp_search(text, sigs[s].pattern); ck += str_cmps;
        }
        printf("   %-19s %-4s naive %d, Rabin-Karp %d, automaton %d, KMP %d  (comparisons: naive %ld, KMP %ld)\n",
               sigs[s].name, sigs[s].pattern, tot[0], tot[1], tot[2], tot[3], cn, ck);
    }
    printf("correlated incidents raised as alerts (first 8):\n");
    int shown = 0;
    for (int i = 0; i < nal && shown < 8; i++)
        if (alerts[i].rule >= 0) {
            printf("   %04d  %-9s %-19s severity %d\n", alerts[i].time, hosts[alerts[i].host].name, sigs[alerts[i].rule].name, alerts[i].severity);
            shown++;
        }
    free(text); free(pp);

    const char *req = "GET /login?user=admin' OR '1'='1 -- admin' OR '1'='1";
    const char *sig = "admin' OR '1'='1";
    printf("\nsignature in a web request: naive %d, Rabin-Karp %d, automaton %d, KMP %d\n",
           naive_search(req, sig), rk_search(req, sig), fa_search(req, sig), kmp_search(req, sig));
}

static void scenarios(void) {
    printf("\n=== Scenario 1: normal operation ===\n");
    LogEvent *ea = malloc(nev * sizeof(LogEvent)), *eb = malloc(nev * sizeof(LogEvent));
    memcpy(ea, events, nev * sizeof(LogEvent));
    scramble(ea, nev);
    memcpy(eb, ea, nev * sizeof(LogEvent));
    merge_sort_ev(ea, nev); quick_sort_ev(eb, 0, nev - 1);
    printf("%d events sorted two ways, identical: %s\n", nev, memcmp(ea, eb, nev * sizeof(LogEvent)) == 0 ? "yes" : "NO");
    int npat = 0;
    for (int i = 0; i < nal; i++) if (alerts[i].rule >= 0) npat++;
    printf("alerts raised: %d high-severity + %d correlated incidents\n", nal - npat, npat);
    free(ea); free(eb);
    Graph g; build_network(&g);
    int d[MAXV], p[MAXV], bf[MAXV];
    dijkstra(&g, 0, d, p); bellman_ford(&g, 0, bf);
    printf("shortest paths from gateway, Dijkstra vs Bellman-Ford:\n");
    for (int i = 0; i < 6; i++) printf("   %-9s %d vs %d\n", hosts[i].name, d[i], bf[i]);

    printf("\n=== Scenario 2: capacity shock ===\n");
    int cap[MAXV][MAXV];
    build_flow(cap);
    printf("link capacities normal : max flow %d Mbps\n", max_flow(cap, 6, 0, 5));
    cap[3][5] = 8;
    printf("database uplink cut 20 -> 8: max flow %d Mbps\n", max_flow(cap, 6, 0, 5));
    int budgets[] = {item_budget(), item_budget() / 2};
    for (int i = 0; i < 2; i++)
        printf("containment budget %2d h: DP value %d, greedy value %d\n",
               budgets[i], knapsack_dp(item_w, item_v, NITEMS, budgets[i]),
               knapsack_greedy(item_w, item_v, NITEMS, budgets[i]));

    printf("\n=== Scenario 3: large-data stress ===\n");
    int n = 100000;
    int *a = malloc(n * sizeof(int)), *b = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++) a[i] = b[i] = rand();
    double t = now_ms(); merge_sort(a, n); double tm = now_ms() - t;
    t = now_ms(); quick_sort(b, 0, n - 1); double tq = now_ms() - t;
    printf("sort 100000 numbers: merge %.1f ms, quick %.1f ms, same result: %s\n", tm, tq,
           memcmp(a, b, n * sizeof(int)) == 0 ? "yes" : "NO");
    free(a); free(b);
    LogEvent *ba = malloc(n * sizeof(LogEvent)), *bb2 = malloc(n * sizeof(LogEvent));
    random_events(ba, n);
    memcpy(bb2, ba, n * sizeof(LogEvent));
    t = now_ms(); merge_sort_ev(ba, n); tm = now_ms() - t;
    t = now_ms(); quick_sort_ev(bb2, 0, n - 1); tq = now_ms() - t;
    printf("sort 100000 event records: merge %.1f ms, quick %.1f ms, same result: %s\n", tm, tq,
           memcmp(ba, bb2, n * sizeof(LogEvent)) == 0 ? "yes" : "NO");
    free(ba); free(bb2);
    int len = 300000;
    char *text = malloc(len + 1), pat[302];
    memset(text, 'a', len); text[len] = 0;
    memset(pat, 'a', 300); pat[300] = 'b'; pat[301] = 0;
    str_cmps = 0; t = now_ms(); int c1 = naive_search(text, pat); double tn = now_ms() - t; long cn = str_cmps;
    str_cmps = 0; t = now_ms(); int c2 = kmp_search(text, pat);   double tk = now_ms() - t; long ck = str_cmps;
    printf("worst-case signature scan over %d chars: naive %.1f ms (%ld comparisons), KMP %.1f ms (%ld), matches %d / %d\n",
           len, tn, cn, tk, ck, c1, c2);
    free(text);
}

static void menu(void) {
    printf("\n==== Security Analytics Engine ====\n"
           " 1 Sorting & searching        5 Flow & matching\n"
           " 2 Divide & conquer           6 Signature matching\n"
           " 3 Greedy                     7 Three scenarios\n"
           " 4 Dynamic programming        8 Benchmarks (writes results.csv)\n"
           " L Load log file              V Validation & indicators\n"
           " T Run self-tests             0 Exit\n> ");
}
int main(void) {
    char line[100];
    srand(1);
    default_events();
    for (;;) {
        menu();
        if (!fgets(line, sizeof line, stdin)) break;
        printf("\n");
        switch (line[0]) {
            case '1': demo_sorting();   break;
            case '2': demo_dnc();       break;
            case '3': demo_greedy();    break;
            case '4': demo_dp();        break;
            case '5': demo_flow();      break;
            case '6': demo_strings();   break;
            case '7': scenarios();      break;
            case '8': run_benchmarks(); break;
            case 'V': case 'v': demo_validation(); break;
            case 'L': case 'l':
                printf("file path (each line: \"time host type severity\", or just \"time\"): ");
                if (fgets(line, sizeof line, stdin)) {
                    line[strcspn(line, "\r\n")] = 0;
                    if (load_logs(line)) printf("loaded %d valid events, rejected %d invalid lines\n", nev, rejected);
                    else printf("could not read file (%d events kept)\n", nev);
                }
                break;
            case 'T': case 't': passed = failed = 0; run_tests(); break;
            case '0': return 0;
            default:  printf("choose 0-8, L, V or T\n");
        }
    }
    return 0;
}
