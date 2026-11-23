"""
Імітаційна модель для перевірки методу CTS.
Дані повністю синтетичні: генеруються стохастичною моделлю сесій REST API
(замовлення/документи). Результати залежать від припущень моделі, описаних у звіті.

Запуск:  python3 cts_sim.py --tables  (УСІ таблиці й числа статті -> папка results/)
         python3 cts_sim.py --tables --quick  (те саме на малому обсязі, лише перевірка)
         python3 cts_sim.py --quick    (перевірка роботи, кілька секунд)
         python3 cts_sim.py --article  (таблиця 1 статті)
         python3 cts_sim.py --fixes    (стрес-перевірка, бутстреп, калібрування)
         python3 cts_sim.py            (пошук 74 конфігурацій + фінальне порівняння)
"""
import random, math, json, sys, bisect
try: 
    sys.stdout.reconfigure(encoding="utf-8", errors="replace"); sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from collections import defaultdict, deque

# ---------------------------------------------------------------- параметри
P = dict(
    n_users_cal=3000, n_users_test=2000, n_attackers_per_type=100,
    orders_per_user=(2, 6), docs_per_order=(1, 4), share_prob=0.10,
    sessions_per_user=(1, 3), actions_per_session=(4, 15),
    beta=0.05,            # частка легітимних читань за прямим посиланням
    shared_list_prob=0.3, # ймовірність, що сесія відкриває /me/shared
    H=60.0, L=24 * 3600.0, windows=(10.0, 600.0, 86400.0), pr4_delta=10.0,
    m_cap=None,           # обмеження кількості калібрувальних користувачів
    gap_mean=8.0,         # середня пауза між легітимними діями, с
    slow_gap=(60, 180),   # інтервал повільного перебору, с
    write_prob=0.0,       # імовірність легітимного редагування (PATCH) після читання
    beta_open=0.0,        # імовірність, що легітимна сесія починається з відкриття власного замовлення за прямим посиланням
                          # (сповіщення, лист); 0 — як в основному експерименті, генератор тоді не змінюється
    order_seen_prob=None, # частка власних замовлень, ключі яких монітор уже бачив у межах L до початку доби
                          # (оформлення, попередні списки); None — передісторію не моделюємо (основний експеримент)
)
ATTACKS = ["guess", "fast_enum", "slow_enum", "chain", "list_leak"]          # використані під час відбору v2
ATTACKS_NEW = ["adaptive", "cautious", "write_bola"]                        # нові, лише для стрес-перевірки
ATTACKS_ALL = ATTACKS + ATTACKS_NEW
ATTACKS_QUIET = ["chain_quiet1", "chain_quiet3"]  # ланцюги, перший запит яких схожий на законне пряме посилання (розділ Д)

# ---------------------------------------------------------------- світ
class World:
    def __init__(s, n_users, rng):
        s.order_owner, s.order_docs, s.doc_order = {}, {}, {}
        s.user_orders, s.shared_with = defaultdict(list), defaultdict(set)  # doc -> users
        s.user_shared = defaultdict(list)
        oid = did = 0
        for u in range(n_users):
            for _ in range(rng.randint(*P["orders_per_user"])):
                oid += 1; s.order_owner[oid] = u; s.user_orders[u].append(oid); s.order_docs[oid] = []
                for _ in range(rng.randint(*P["docs_per_order"])):
                    did += 1; s.order_docs[oid].append(did); s.doc_order[did] = oid
        s.n_orders, s.n_docs, s.n_users = oid, did, n_users
        for d in range(1, did + 1):
            if rng.random() < P["share_prob"]:
                v = rng.randrange(n_users)
                if v != s.order_owner[s.doc_order[d]]:
                    s.shared_with[d].add(v); s.user_shared[v].append(d)

    def allowed(s, u, kind, key):
        if kind == "order": return s.order_owner[key] == u
        return s.order_owner[s.doc_order[key]] == u or u in s.shared_with[key]

def ev(t, sess, op, o=None, p=None, issued=(), root=False):
    return dict(t=t, sess=sess, op=op, o=o, p=p, issued=list(issued), root=root, y=0, atk=None)

def legit_session(W, u, t, sess, rng, beta):
    E, opened = [], False
    def gap(): return 1.0 + rng.expovariate(1 / P["gap_mean"])
    def root_orders():
        nonlocal t, opened
        E.append(ev(t, sess, "LIST", issued=[("order", o) for o in W.user_orders[u]], root=True)); opened = True
        t += gap()
        if W.user_shared[u] and rng.random() < P["shared_list_prob"]:
            E.append(ev(t, sess, "LIST_SHARED", issued=[("doc", d) for d in W.user_shared[u]], root=True)); t += gap()
    read_docs = []
    if P["beta_open"] > 0 and rng.random() < P["beta_open"]:  # пряме посилання на власне замовлення, без списку
        o = rng.choice(W.user_orders[u])
        E.append(ev(t, sess, "OPEN", ("order", o), None, [("doc", d) for d in W.order_docs[o]])); t += gap()
        for d in rng.sample(W.order_docs[o], rng.randint(1, len(W.order_docs[o]))):
            E.append(ev(t, sess, "READ", ("doc", d), ("order", o))); read_docs.append(d); t += 1.0 + rng.uniform(1, 12)
    for _ in range(rng.randint(*P["actions_per_session"])):
        r = rng.random()
        if r < beta:  # пряме посилання (закладка, лист колеги)
            pool = [d for o in W.user_orders[u] for d in W.order_docs[o]] + W.user_shared[u]
            d = rng.choice(pool)
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += gap()
        elif r < beta + 0.10 and read_docs:  # повторне читання
            d = rng.choice(read_docs); E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += gap()
        elif r < beta + 0.18 and W.user_shared[u]:  # спільний документ зі списку
            if not opened: root_orders()
            d = rng.choice(W.user_shared[u])
            E.append(ev(t, sess, "LIST_SHARED", issued=[("doc", x) for x in W.user_shared[u]], root=True)); t += gap()
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += gap()
        else:  # звичайна навігація: список -> замовлення -> документи
            if not opened: root_orders()
            o = rng.choice(W.user_orders[u])
            E.append(ev(t, sess, "OPEN", ("order", o), None, [("doc", d) for d in W.order_docs[o]])); t += gap()
            for d in rng.sample(W.order_docs[o], rng.randint(1, len(W.order_docs[o]))):
                E.append(ev(t, sess, "READ", ("doc", d), ("order", o))); read_docs.append(d)
                t += 1.0 + rng.uniform(1, 12)
                if P["write_prob"] > 0 and rng.random() < P["write_prob"]:
                    E.append(ev(t, sess, "PATCH", ("doc", d), ("order", o))); t += 1.0 + rng.uniform(1, 12)
    return E, t

def attack_session(W, u, t, sess, kind, rng):
    E = []
    foreign_docs = lambda: [d for d in range(1, W.n_docs + 1)]
    if kind == "guess":
        for _ in range(2):
            d = rng.randint(1, W.n_docs)
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += rng.uniform(5, 60)
    elif kind in ("fast_enum", "slow_enum"):
        d0 = rng.randint(1, W.n_docs - 40)
        for i in range(30):
            d = d0 + i
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d])))
            t += rng.uniform(0.3, 2.0) if kind == "fast_enum" else rng.uniform(*P["slow_gap"])
    elif kind == "chain":
        for _ in range(3):
            o = rng.randint(1, W.n_orders)
            E.append(ev(t, sess, "OPEN", ("order", o), None, [("doc", d) for d in W.order_docs[o]])); t += rng.uniform(2, 10)
            for d in W.order_docs[o]:
                E.append(ev(t, sess, "READ", ("doc", d), ("order", o))); t += rng.uniform(2, 10)
    elif kind in ("chain_quiet1", "chain_quiet3"):  # ланцюг у темпі звичайної навігації: чуже замовлення -> його документи
        for i in range(1 if kind == "chain_quiet1" else 3):
            o = rng.randint(1, W.n_orders)
            E.append(ev(t, sess, "OPEN", ("order", o), None, [("doc", d) for d in W.order_docs[o]])); t += 1.0 + rng.expovariate(1 / P["gap_mean"])
            for d in W.order_docs[o]:
                E.append(ev(t, sess, "READ", ("doc", d), ("order", o))); t += 1.0 + rng.uniform(1, 12)
            t += rng.uniform(30, 120)
    elif kind == "list_leak":  # коренева операція з надмірним розкриттям (порушення A1)
        leak = rng.sample(range(1, W.n_docs + 1), 60)
        E.append(ev(t, sess, "LIST_FEED", issued=[("doc", d) for d in leak], root=True)); t += rng.uniform(2, 6)
        for d in leak[:20]:
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += rng.uniform(3, 12)
    elif kind == "adaptive":  # перемежовує чужі читання з легітимною навігацією, повільний темп
        own = W.user_orders[u]
        E.append(ev(t, sess, "LIST", issued=[("order", o) for o in own], root=True)); t += rng.uniform(2, 8)
        for _ in range(15):
            o = rng.choice(own)
            E.append(ev(t, sess, "OPEN", ("order", o), None, [("doc", d) for d in W.order_docs[o]])); t += rng.uniform(2, 8)
            d = rng.choice(W.order_docs[o]); E.append(ev(t, sess, "READ", ("doc", d), ("order", o))); t += rng.uniform(2, 8)
            d = rng.randint(1, W.n_docs); E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d])))
            t += rng.uniform(60, 300)
    elif kind == "cautious":  # 4 чужі читання на добу з інтервалом 0,5-3 год
        for _ in range(4):
            d = rng.randint(1, W.n_docs)
            E.append(ev(t, sess, "READ", ("doc", d), ("order", W.doc_order[d]))); t += rng.uniform(1800, 10800)
    elif kind == "write_bola":  # BOLA на зміну: PATCH чужих документів
        for _ in range(10):
            d = rng.randint(1, W.n_docs)
            E.append(ev(t, sess, "PATCH", ("doc", d), ("order", W.doc_order[d]))); t += rng.uniform(2, 10)
    for e in E:
        if e["o"] is not None:
            e["y"] = 0 if W.allowed(u, e["o"][0], e["o"][1]) else 1
            e["atk"] = kind
    return E, t

def user_day(W, u, rng, beta, attack=None):
    E, sid = [], 0
    if P["order_seen_prob"] is not None:  # передісторія: ключі замовлень, видані підтриманими подіями раніше (у межах L)
        seen = [o for o in W.user_orders[u] if rng.random() < P["order_seen_prob"]]
        E.append(ev(-1.0, (u, "prior"), "PRIOR_LIST", issued=[("order", o) for o in seen], root=True))
    starts = sorted(rng.uniform(0, 20 * 3600) for _ in range(rng.randint(*P["sessions_per_user"])))
    for i, t0 in enumerate(starts):
        ev_, _ = legit_session(W, u, t0, (u, i), rng, beta); E += ev_
    if attack:
        t0 = rng.uniform(0, 20 * 3600)
        pre, t = legit_session(W, u, t0, (u, "atk"), rng, beta)  # атакувальник спершу поводиться легітимно
        pre = pre[: rng.randint(2, 6)]
        t = pre[-1]["t"] + 5 if pre else t0
        atk, _ = attack_session(W, u, t, (u, "atk"), attack, rng); E += pre + atk
    E.sort(key=lambda e: e["t"])
    return E

# ---------------------------------------------------------------- ознаки
def features(E, W):
    """Потокове обчислення ознак для подій одного суб'єкта (у порядку часу)."""
    H, L, wins = P["H"], P["L"], P["windows"]
    sup, sup0 = {}, {}            # ключ -> час закінчення TTL (рекурсивна / нерекурсивна)
    anch, anch0 = {}, {}          # ключ замовлення -> (t, issued)
    hist = deque()                # (t, target) для вікон
    pr4 = deque()                 # (t, target, K_pr4)
    sess_targets = defaultdict(set)
    out = []
    for e in E:
        t, o = e["t"], e["o"]
        if o is not None:
            g = int(sup.get(o, -1) >= t); g0 = int(sup0.get(o, -1) >= t)
            def epis(A, with_s=True):
                best = 0
                if e["op"] in ("READ", "PATCH") and e["p"] in A:
                    te, iss = A[e["p"]]
                    if t - H <= te < t:
                        G = int(o in iss)
                        S = int(W.doc_order[o[1]] == e["p"][1]) if with_s else 0
                        best = G + S
                return best
            K, K0, Kns, K0ns = epis(anch), epis(anch0), epis(anch, False), epis(anch0, False)
            c_now = g + K
            hist.append((t, o, c_now, g0 + K0, g0, g + Kns, g0 + K0ns))
            while hist and hist[0][0] <= t - wins[-1]: hist.popleft()
            N = [len({h[1] for h in hist if h[0] > t - w}) for w in wins]
            Nw = [len({h[1] for h in hist if h[0] > t - w and h[2] <= 1}) for w in wins]
            Nw0 = [len({h[1] for h in hist if h[0] > t - w and h[3] <= 1}) for w in wins]
            Nt = {thr: [len({h[1] for h in hist if h[0] > t - w and h[2] <= thr}) for w in wins] for thr in (0, 2)}
            Nt[1] = Nw
            Nl = [len({h[1] for h in hist if h[0] > t - w and h[4] == 0}) for w in wins]
            Nns = [len({h[1] for h in hist if h[0] > t - w and h[5] <= 1}) for w in wins]
            N0ns = [len({h[1] for h in hist if h[0] > t - w and h[6] <= 1}) for w in wins]
            n10 = sum(1 for h in hist if h[0] > t - 10.0)
            # PR4: K без рекурсії, B — різні цілі за 10 с з K<2
            pr4.append((t, o, K0))
            while pr4 and pr4[0][0] <= t - P["pr4_delta"]: pr4.popleft()
            B = len({x for (tt, x, k) in pr4 if k < 2})
            sess_targets[e["sess"]].add(o)
            out.append(dict(e=e, cls=e["op"], c=g + K, c0=g0 + K0, cns=g + Kns, c0ns=g0 + K0ns, N0ns=N0ns, g0=g0, N=N, n10=n10,
                            Nw=Nw, Nns=Nns, Nt=Nt, K=K, g=g, Nw0=Nw0, Nl=Nl, pr4=K0 * 1000 - B, sessN=len(sess_targets[e["sess"]])))
            supported = g == 1
        else:
            supported = e["root"]
        # оновлення після відповіді (поточний запит уже оцінено)
        for k in e["issued"]:
            sup0[k] = t + L
            if supported: sup[k] = t + L
        if e["op"] == "OPEN":
            anch0[o] = (t, set(e["issued"]))
            if supported: anch[o] = (t, set(e["issued"]))
    return out

# ---------------------------------------------------------------- методи
def ch_c(r): return r["c"]
def ch_lex(r): return 2 * r["K"] + r["g"]          # спершу епізодна підтримка K*, потім глобальна g
def chN(key, thr, k): return (lambda r: -r[key][thr][k]) if key == "Nt" else (lambda r: -r[key][k])

WIN = {"10s": (0,), "10s+10m": (0, 1), "10s+10m+24h": (0, 1, 2), "10s+24h": (0, 2)}

def cts_variant(ctx="c", thr=1, win="10s+10m+24h", combo="min"):
    cf = ch_c if ctx == "c" else ch_lex
    chans = [cf] + ([chN("Nt", thr, k) for k in WIN[win]] if win else [])
    return (chans, combo)

def baselines():
    Nch = [chN("N", None, k) for k in range(3)]
    Nw0 = [chN("Nw0", None, k) for k in range(3)]
    Nl = [chN("Nl", None, k) for k in range(3)]
    return {
        "CTS v1 (повний профіль, ЕТАП 5)":  cts_variant(),
        "CTS v1 (профіль 10 с, ЕТАП 5)":    cts_variant(win="10s"),
        "Абляція: без рекурсії":           ([lambda r: r["c0"]] + Nw0, "min"),
        "CTS з ПР № 4 (лекс. K,−B)":        ([lambda r: r["pr4"]], "min"),
        "Аналог Lin et al. (E_u,r + N)":    ([lambda r: r["g0"]] + Nl, "min"),
        "Новий ID":                        ([lambda r: r["g0"]], "min"),
        "Частота (запити за 10 с)":        ([lambda r: -r["n10"]], "min"),
        "Різні об'єкти в сесії":            ([lambda r: -r["sessN"]], "min"),
        "Абляція: N за всіма цілями":      ([ch_c] + Nch, "min"),
    }

# ---------------------------------------------------------------- конформне калібрування
class Calib:
    """Mondrian-калібрування за класом операції.
    combo='bonf'  : p = min(1, J*min_j p_j)                       
    combo='min'   : двоетапне; s = min_j p^A_j                    
    combo='fisher': двоетапне; s = sum_j log p^A_j
    combo='tail'  : двоетапне; s = частка точок A, що не менш підозрілі за запит у КОЖНОМУ каналі
    У двоетапних варіантах функція s фіксована при відомій половині A, тож p з половини B валідне."""
    def __init__(s, rows_by_user, chans, rng, m_cap=None, combo="min", weighted=False):
        # rows_by_user: {користувач: його запити}; половини A і B формуються з різних користувачів
        sess = list(rows_by_user.values()); rng.shuffle(sess)
        if m_cap: sess = sess[:m_cap]
        if weighted:  # вибір користувачів з імовірністю, пропорційною кількості запитів (з поверненням)
            w = [len(x) for x in sess]; sess = rng.choices(sess, weights=w, k=len(sess))
        s.chans, s.combo = chans, (combo if len(chans) > 1 else "bonf")
        def pick(group):
            out = defaultdict(list)
            for rows in group:
                by = defaultdict(list)
                for r in rows: by[r["cls"]].append(r)
                for cl, rs in by.items(): out[cl].append(rng.choice(rs))
            return out
        if s.combo == "bonf":
            s.ref = {cl: [sorted(f(r) for r in rs) for f in chans] for cl, rs in pick(sess).items()}
            s.m = {cl: len(v[0]) for cl, v in s.ref.items()}
        else:
            h = len(sess) // 2
            A, B = pick(sess[:h]), pick(sess[h:])
            s.refA = {cl: [sorted(f(r) for r in rs) for f in chans] for cl, rs in A.items()}
            s.ptsA = {cl: [tuple(f(r) for f in chans) for r in rs] for cl, rs in A.items()}
            s.cache = {}
            s.refB = {cl: sorted(s._score(r, cl) for r in rs) for cl, rs in B.items()}
            s.m = {cl: len(v) for cl, v in s.refB.items()}
    @staticmethod
    def _p(ref, x, U):
        lo = bisect.bisect_left(ref, x); hi = bisect.bisect_right(ref, x)
        return (lo + U * (1 + hi - lo)) / (len(ref) + 1)
    def _score(s, r, cl):
        if cl not in s.refA: cl = "READ"
        v = tuple(f(r) for f in s.chans)
        key = (cl, v)
        if key in s.cache: return s.cache[key]
        if s.combo == "tail":
            pts = s.ptsA[cl]
            val = (1 + sum(1 for x in pts if all(a <= b for a, b in zip(x, v)))) / (len(pts) + 1)
        else:
            ps = [s._p(s.refA[cl][j], v[j], 0.5) for j in range(len(v))]
            val = min(ps) if s.combo == "min" else sum(math.log(p) for p in ps)
        s.cache[key] = val
        return val
    def pval(s, r, U):
        cl = r["cls"]
        if cl not in (s.ref if s.combo == "bonf" else s.refB): cl = "READ"  # клас без калібрування
        if s.combo == "bonf":
            ps = [s._p(s.ref[cl][j], f(r), U) for j, f in enumerate(s.chans)]
            return min(1.0, len(ps) * min(ps))
        return s._p(s.refB[cl], s._score(r, cl), U)

# ---------------------------------------------------------------- статистика
def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"),) * 3
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0, c - h), min(1, c + h)

def avg_precision(scores, labels):
    pairs = sorted(zip(scores, labels))
    tp = fp = 0; npos = sum(labels); ap = 0.0
    for _, y in pairs:
        if y: tp += 1; ap += tp / (tp + fp)
        else: fp += 1
    return ap / npos if npos else float("nan")

# ---------------------------------------------------------------- генерація даних і оцінювання
def make_data(seed, beta=None, scale=1.0, attacks=None, raw=None):
    """raw — необов'язковий словник; якщо задано, у нього зберігаються сирі події (для базової конструкції з блокуванням доказів)."""
    attacks = attacks or ATTACKS
    rng = random.Random(seed)
    beta = P["beta"] if beta is None else beta
    nc, nt, na = int(P["n_users_cal"] * scale), int(P["n_users_test"] * scale), int(P["n_attackers_per_type"] * scale)
    Wc = World(nc, rng); Wt = World(nt + na * len(attacks), rng)
    cal_rows = defaultdict(list)
    for u in range(nc):
        Eu = user_day(Wc, u, rng, beta)
        if raw is not None: raw.setdefault("cal", []).append((Eu, Wc))
        for r in features(Eu, Wc): cal_rows[u].append(r)  # одиниця калібрування — користувач (теорема 1)
    test = []
    for u in range(nt + na * len(attacks)):
        a = None if u < nt else attacks[(u - nt) // na]
        Eu = user_day(Wt, u, rng, beta, a)
        if raw is not None: raw.setdefault("test", []).append((Eu, Wt, a))
        fs = features(Eu, Wt)
        for r in fs: r["attacker_user"] = a is not None
        test += fs
    return cal_rows, test

def evaluate(cal_rows, test, spec, seed, alphas=(0.01, 0.05), m_cap=None, attacks=None,
             U_fixed=None, weighted=False, cal_seed=None, per_sess=False, return_pv=False):
    """U_fixed=1.0 — детермінований консервативний варіант; weighted=True — калібрування,
    зважене за довжиною сесій (гарантія для сукупної FPR за всіма запитами)."""
    ATTACKS = attacks or globals()["ATTACKS"]
    chans, combo = spec
    cal = Calib(cal_rows, chans, random.Random(seed + 7 if cal_seed is None else cal_seed), m_cap or P["m_cap"], combo, weighted)
    rng = random.Random(seed + 3)
    pv = [cal.pval(r, U_fixed if U_fixed is not None else rng.random()) for r in test]
    R = {"AP": avg_precision(pv, [r["e"]["y"] for r in test]), "m": cal.m, "uniq": len(getattr(cal, "cache", {}))}
    if return_pv: R["pv"] = pv
    if per_sess:
        ps = {}
        for r, p in zip(test, pv):
            e = r["e"]
            if e["y"] == 1:
                x = ps.setdefault(e["sess"], [e["atk"], {a: 0 for a in alphas}, 0]); x[2] += 1
                for a in alphas: x[1][a] += p <= a
        R["per_sess"] = ps
    for a in alphas:
        st = defaultdict(lambda: [0, 0]); sessdet = defaultdict(set); sessall = defaultdict(set)
        first = {}; idx = defaultdict(int); rand_leg = defaultdict(list)
        for r, p in zip(test, pv):
            e = r["e"]; flag = p <= a
            if not r["attacker_user"]:
                st["legit"][0] += flag; st["legit"][1] += 1; rand_leg[(e["sess"][0], r["cls"])].append(flag)  # як у теоремі 1: для кожного користувача й класу операцій — один випадковий запит
            if e["y"] == 1:
                k = e["atk"]; st[k][0] += flag; st[k][1] += 1; sessall[k].add(e["sess"])
                idx[e["sess"]] += 1
                if flag:
                    sessdet[k].add(e["sess"]); first.setdefault(e["sess"], idx[e["sess"]])
        rr = random.Random(seed + 11)
        fl = []; fcl = defaultdict(lambda: [0, 0])
        for (uu, cl), v in sorted(rand_leg.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
            x = rr.choice(v); fl.append(x); fcl[cl][0] += x; fcl[cl][1] += 1
        R[a] = dict(FPR=st["legit"], FPR_rand=[sum(fl), len(fl)], FPR_cls=dict(fcl),
                    rec={k: st[k] for k in ATTACKS},
                    sess={k: [len(sessdet[k]), len(sessall[k])] for k in ATTACKS},
                    delay={k: (sum(first[s] for s in sessdet[k]) / len(sessdet[k]) if sessdet[k] else None) for k in ATTACKS},
                    TP=sum(st[k][0] for k in ATTACKS), FP=st["legit"][0])
    return R

def macro(R, a, attacks=None):
    attacks = attacks or ATTACKS
    return sum(R[a]["rec"][k][0] / max(1, R[a]["rec"][k][1]) for k in attacks) / len(attacks)

def log(*x):
    print(*x, flush=True)

def table(results, a, title, attacks=None):
    ATTACKS = attacks or globals()["ATTACKS"]
    """results: {name: [R_seed1, R_seed2, ...]} -> друк таблиці в консоль."""
    log(f"\n{title}  (alpha = {a})")
    hdr = f"{'Метод':40s} {'FPR%':>6s} " + " ".join(f"{k[:10]:>10s}" for k in ATTACKS) + f" {'Сер.':>6s} {'AP':>6s}"
    log(hdr); log("-" * len(hdr))
    for name, Rs in results.items():
        fk = sum(R[a]["FPR_rand"][0] for R in Rs); fn = sum(R[a]["FPR_rand"][1] for R in Rs)
        rec = [sum(R[a]["rec"][k][0] for R in Rs) / max(1, sum(R[a]["rec"][k][1] for R in Rs)) for k in ATTACKS]
        ap = sum(R["AP"] for R in Rs) / len(Rs)
        log(f"{name[:40]:40s} {100*fk/fn:6.2f} " + " ".join(f"{x:10.2f}" for x in rec) + f" {sum(rec)/len(rec):6.3f} {ap:6.3f}")

# ---------------------------------------------------------------- режими запуску
def mode_search(dev_seeds=(301, 302, 303), scale=0.5):
    grid = {}
    for ctx in ("c", "lex"):
        for thr in (0, 1, 2):
            for win in ("10s", "10s+10m", "10s+10m+24h", "10s+24h"):
                for combo in ("min", "fisher", "tail"):
                    grid[f"ctx={ctx} thr<={thr} win={win} comb={combo}"] = dict(ctx=ctx, thr=thr, win=win, combo=combo)
        grid[f"ctx={ctx} без N"] = dict(ctx=ctx, win=None)
    res = defaultdict(list)
    for i, sd in enumerate(dev_seeds):
        log(f"[пошук] сід {sd} ({i+1}/{len(dev_seeds)}): генерація даних..."); cal, test = make_data(sd, scale=scale)
        for j, (name, spec) in enumerate(grid.items()):
            res[name].append(evaluate(cal, test, cts_variant(**spec), sd, alphas=(0.01,)))
            if (j + 1) % 10 == 0: log(f"   оцінено варіантів: {j+1}/{len(grid)}")
    ranked = sorted(res, key=lambda n: (-sum(macro(R, 0.01) for R in res[n]), -sum(R["AP"] for R in res[n])))
    table({n: res[n] for n in ranked[:15]}, 0.01, "ТОП-15 варіантів на сідах розробки (критерій: середня повнота за 5 типами атак)")
    json.dump({n: res[n] for n in ranked}, open("search.json", "w", encoding="utf-8"), ensure_ascii=False, default=str)
    return ranked[0], grid[ranked[0]]

def mode_final(params, seeds=(401, 402, 403, 404, 405), scale=1.0):
    methods = {"CTS v2 (обраний варіант)": cts_variant(**params)}; methods.update(baselines())
    res = defaultdict(list)
    for i, sd in enumerate(seeds):
        log(f"[фінал] сід {sd} ({i+1}/{len(seeds)}): генерація даних..."); cal, test = make_data(sd, scale=scale)
        for name, sp in methods.items(): res[name].append(evaluate(cal, test, sp, sd))
    for a in (0.01, 0.05): table(res, a, "ФІНАЛЬНЕ ПОРІВНЯННЯ на нових сідах")
    json.dump(res, open("final.json", "w", encoding="utf-8"), ensure_ascii=False, default=str)
    return res

def mode_sens(params):
    methods = {"CTS v2": cts_variant(**params), "CTS v1 (повний)": cts_variant(), "Аналог Lin et al.": baselines()["Аналог Lin et al. (E_u,r + N)"]}
    out = {}
    for b in (0.0, 0.05, 0.15):
        log(f"[чутливість] beta={b}"); cal, test = make_data(501, beta=b)
        out[f"beta={b}"] = {n: [evaluate(cal, test, sp, 501, alphas=(0.01,))] for n, sp in methods.items()}
        table(out[f"beta={b}"], 0.01, f"Чутливість: частка прямих посилань beta = {b}")
    json.dump(out, open("sens.json", "w", encoding="utf-8"), ensure_ascii=False, default=str)


V2 = dict(ctx="c", thr=1, win="10s+24h", combo="tail")
def cts_final():
    """Модель зі статті: c = g + K* (без S), слабка підтримка c <= 1, вікна 10 с і 24 год, домінування."""
    return ([lambda r: r["cns"], lambda r: -r["Nns"][0], lambda r: -r["Nns"][2]], "tail")

def boot_diff(psA, psB, attacks, a=0.01, B=1000, seed=0):
    """Парний бутстреп за атакувальними сесіями: різниця середньої повноти (A − B) і 95 % ДІ."""
    rng = random.Random(seed)
    by = defaultdict(list)
    for sid, (k, fl, n) in psA.items(): by[k].append(sid)
    def mac(sample):
        tot = 0
        for k in attacks:
            ids = sample[k]
            fa = sum(psA[i][1][a] for i in ids); fb = sum(psB[i][1][a] for i in ids); n = sum(psA[i][2] for i in ids)
            tot += (fa - fb) / max(1, n)
        return tot / len(attacks)
    point = mac({k: by[k] for k in attacks})
    ds = sorted(mac({k: [rng.choice(by[k]) for _ in by[k]] for k in attacks}) for _ in range(B))
    return point, ds[int(0.025 * B)], ds[int(0.975 * B) - 1]

def mode_fixes():
    out = {}
    base = baselines()
    M = {"CTS v2": cts_variant(**V2), "CTS v1 (повний)": base["CTS v1 (повний профіль, ЕТАП 5)"],
         "CTS v1 (10 с)": base["CTS v1 (профіль 10 с, ЕТАП 5)"], "Аналог Lin et al.": base["Аналог Lin et al. (E_u,r + N)"],
         "Новий ID": base["Новий ID"]}
    # F2, F3, F5 — на фінальних сідах 401-405
    acc = defaultdict(list); ps_all = defaultdict(dict); uniq = []
    for sd in (401, 402, 403, 404, 405):
        log(f"[виправлення] сід {sd}: генерація даних..."); cal, test = make_data(sd)
        for n, sp in M.items():
            R = evaluate(cal, test, sp, sd, alphas=(0.01,), per_sess=True)
            acc[n].append(R); ps_all[n].update({(sd, k): v for k, v in R["per_sess"].items()})
            if n == "CTS v2": uniq.append(R["uniq"])
        acc["CTS v2, U = 1 (детермінований)"].append(evaluate(cal, test, cts_variant(**V2), sd, alphas=(0.01,), U_fixed=1.0))
        acc["CTS v2, калібрування зважене за довжиною сесій"].append(evaluate(cal, test, cts_variant(**V2), sd, alphas=(0.01,), weighted=True))
    table(acc, 0.01, "F2/F5: детермінований і зважений варіанти (сіди 401-405)")
    for n, Rs in acc.items():
        fk = sum(R[0.01]["FPR"][0] for R in Rs); fn = sum(R[0.01]["FPR"][1] for R in Rs)
        log(f"   сукупна FPR (усі легітимні запити) — {n}: {100*fk/fn:.2f} %")
    log(f"   унікальних векторів ознак (кеш домінування) на сід: {uniq}")
    out["F2F5"] = acc
    log("\nF3: парні бутстреп-ДІ різниці середньої повноти (CTS v2 мінус метод), alpha = 0.01")
    out["F3"] = {}
    for n in ("CTS v1 (повний)", "CTS v1 (10 с)", "Аналог Lin et al.", "Новий ID"):
        d = boot_diff(ps_all["CTS v2"], ps_all[n], ATTACKS)
        out["F3"][n] = d; log(f"   v2 − {n:22s}: {d[0]:+.3f}  [{d[1]:+.3f}; {d[2]:+.3f}]")
    # F4 — умовна мінливість FPR при різних калібрувальних вибірках
    log("\nF4: мінливість FPR між реалізаціями калібрування (сід 401, 30 повторів)")
    cal, test = make_data(401)
    f = []
    for k in range(30):
        R = evaluate(cal, test, cts_variant(**V2), 401, alphas=(0.01,), cal_seed=1000 + k)
        f.append(100 * R[0.01]["FPR"][0] / R[0.01]["FPR"][1])
    f.sort(); mB = R["m"]
    log(f"   m_B = {mB}; FPR, %: мін {f[0]:.2f}, медіана {f[15]:.2f}, макс {f[-1]:.2f}")
    for eps in (0.005, 0.0025):
        log(f"   оцінка m_B для |FPR − 0,01| ≤ {eps} з імовірністю 0,95: ≈ {math.ceil(1.96**2 * 0.01 * 0.99 / eps**2)}")
    out["F4"] = dict(fpr=f, m=mB)
    # F1 — стрес-перевірка на змінених параметрах генератора і нових атаках (не використовувались у відборі)
    log("\nF1: стрес-перевірка (сіди 601-602, нові атаки, легітимні PATCH)")
    scen = {
        "S0 базовий + нові атаки": {},
        "S1 довгі сесії (10-40 дій)": dict(actions_per_session=(10, 40)),
        "S2 короткі сесії (2-6 дій)": dict(actions_per_session=(2, 6)),
        "S3 частка спільних документів 0,3": dict(share_prob=0.3),
        "S4 швидкий легітимний темп (3 с)": dict(gap_mean=3.0),
        "S5 повільний легітимний темп (30 с)": dict(gap_mean=30.0),
        "S6 повільніший перебір (5-15 хв)": dict(slow_gap=(300, 900)),
        "S7 більше сесій (3-6 на добу)": dict(sessions_per_user=(3, 6)),
        "S8 прямі посилання beta = 0,10": dict(beta=0.10),
    }
    saved = dict(P); out["F1"] = {}
    for name, ch in scen.items():
        P.update(saved); P.update(write_prob=0.1); P.update(ch)
        res = defaultdict(list)
        for sd in (601, 602):
            cal, test = make_data(sd, scale=0.6, attacks=ATTACKS_ALL)
            for n, sp in M.items(): res[n].append(evaluate(cal, test, sp, sd, alphas=(0.01,), attacks=ATTACKS_ALL))
        table(res, 0.01, name, attacks=ATTACKS_ALL); out["F1"][name] = res
    P.clear(); P.update(saved)
    for Rs in out["F2F5"].values():
        for R in Rs: R.pop("per_sess", None)
    json.dump(out, open("fixes.json", "w", encoding="utf-8"), ensure_ascii=False, default=str)

def mode_article():
    """Відтворює таблицю 1 статті (сіди 401-405, рандомізоване U для всіх методів)."""
    b = baselines()
    M = {"Запропонований CTS": cts_final(),
         "CTS без рекурсії": ([lambda r: r["c0"], chN("Nw0", None, 0), chN("Nw0", None, 2)], "tail"),
         "CTS без каналів перебору": cts_variant(ctx="c", win=None),
         "CTS лише з вікном 10 с": cts_variant(ctx="c", thr=1, win="10s", combo="tail"),
         "Ознаки Lin et al.": b["Аналог Lin et al. (E_u,r + N)"],
         "Новий ідентифікатор": b["Новий ID"],
         "Кількість об'єктів у сесії": b["Різні об'єкти в сесії"],
         "Частота запитів (10 с)": b["Частота (запити за 10 с)"]}
    res = defaultdict(list)
    for sd in (401, 402, 403, 404, 405):
        log(f"[стаття] сід {sd}: генерація даних..."); cal, test = make_data(sd)
        for n, sp in M.items(): res[n].append(evaluate(cal, test, sp, sd))
        res["Запропонований CTS, U = 1"].append(evaluate(cal, test, cts_final(), sd, U_fixed=1.0))
        res["Запропонований CTS, зважене калібрування"].append(evaluate(cal, test, cts_final(), sd, weighted=True))

    for a in (0.01, 0.05): table(res, a, "ТАБЛИЦЯ 1 СТАТТІ")


# ---------------------------------------------------------------- базова конструкція: походження з блокуванням доказів за сигналом
def features_lin_gated(E, W, decide):
    """Власна базова конструкція (ідея блокування доказів від ризикових запитів — з [19]; це НЕ відтворення [19],
    яке неможливе за опублікованими даними). Об'єкти з відповіді додаються до множини доказів
    лише тоді, коли сам запит не отримав сигналу ризику (decide(row) == False). Рекурсивної умови
    походження немає: довіра залежить від рішення детектора, а не від того, звідки взято ключ."""
    L, wins = P["L"], P["windows"]
    sup = {}; hist = deque(); out = []
    for e in E:
        t, o = e["t"], e["o"]
        if o is not None:
            g = int(sup.get(o, -1) >= t)
            hist.append((t, o, g))
            while hist and hist[0][0] <= t - wins[-1]: hist.popleft()
            Nl = [len({h[1] for h in hist if h[0] > t - w and h[2] == 0}) for w in wins]
            r = dict(e=e, cls=e["op"], g0=g, Nl=Nl)
            out.append(r)
            trusted = not decide(r)
        else:
            trusted = e["root"]
        if trusted:
            for k in e["issued"]: sup[k] = t + L
    return out


def quiet_chain_stats(test, pv, a, kind):
    """Для тихих ланцюгів: частка сесій, перший атакувальний запит яких НЕ отримав сигналу,
    і повнота на наступних запитах ланцюга саме в таких сесіях (головний сценарій теореми 2)."""
    by = defaultdict(list)
    for r, p in zip(test, pv):
        e = r["e"]
        if e["y"] == 1 and e["atk"] == kind: by[e["sess"]].append((e["t"], p <= a))
    n_s = n_quiet = hit = tot = 0
    for v in by.values():
        v.sort(); n_s += 1
        if not v[0][1]:
            n_quiet += 1; tot += len(v) - 1; hit += sum(f for _, f in v[1:])
    return n_quiet / max(1, n_s), (hit / tot if tot else float("nan")), n_quiet

def lin_gated_data(seed, raw, alpha_gate=0.01, scale=1.0, beta=None):
    """Пілотне калібрування на окремому сіді -> рішення для блокування; далі ознаки калібрувальних
    і тестових даних обчислюються однаково, тож обмінність для конформної гарантії зберігається."""
    spec = baselines()["Аналог Lin et al. (E_u,r + N)"]
    pc, _ = make_data(seed + 7000, scale=0.5 * scale, beta=beta)
    C0 = Calib(pc, spec[0], random.Random(seed + 7001), None, spec[1])
    decide = lambda r: C0.pval(r, 1.0) <= alpha_gate
    cal = defaultdict(list)
    for Eu, Wc in raw["cal"]:
        for r in features_lin_gated(Eu, Wc, decide): cal[r["e"]["sess"][0]].append(r)  # групування за користувачем
    test = []
    for Eu, Wt, a in raw["test"]:
        for r in features_lin_gated(Eu, Wt, decide):
            r["attacker_user"] = a is not None; test.append(r)
    return cal, test, spec

# ---------------------------------------------------------------- ТАБЛИЦІ ДЛЯ СТАТТІ (--tables)
# Усі методи зі статті визначено тут в одному місці, на ознаках остаточної моделі (c = g + K*, без S).
import os, csv, zipfile
from xml.sax.saxutils import escape

ATK_UA = {"guess": "Вгад.", "fast_enum": "Швидкий перебір", "slow_enum": "Повільний перебір",
          "chain": "Ланцюг", "list_leak": "Витік через список", "adaptive": "Перемежований перебір",
          "cautious": "«Обережне» читання", "write_bola": "BOLA на зміну",
          "chain_quiet1": "Тихий ланцюг (1 замовлення)", "chain_quiet3": "Тихий ланцюг (3 замовлення)"}

def article_methods():
    b = baselines()
    return {
        "Запропонований CTS": cts_final(),
        "– без рекурсивної підтримки": ([lambda r: r["c0ns"], lambda r: -r["N0ns"][0], lambda r: -r["N0ns"][2]], "tail"),
        "– без каналів перебору": ([lambda r: r["cns"]], "tail"),
        "– лише вікно 10 с": ([lambda r: r["cns"], lambda r: -r["Nns"][0]], "tail"),
        "Походження з блокуванням доказів за сигналом (без рекурсії)": "LIN_GATED",
        "Новий ідентифікатор": b["Новий ID"],
        "Кількість різних об'єктів у сесії": b["Різні об'єкти в сесії"],
        "Частота запитів (10 с)": b["Частота (запити за 10 с)"],
    }
ABLATIONS = ("– без рекурсивної підтримки", "– без каналів перебору", "– лише вікно 10 с")
LIN = "Походження з блокуванням доказів за сигналом (без рекурсії)"

def agg_rec(Rs, a, k):
    return sum(R[a]["rec"][k][0] for R in Rs) / max(1, sum(R[a]["rec"][k][1] for R in Rs))
def agg_fpr(Rs, a, key="FPR_rand"):
    return sum(R[a][key][0] for R in Rs), sum(R[a][key][1] for R in Rs)
def agg_sess(Rs, a, k):
    return sum(R[a]["sess"][k][0] for R in Rs) / max(1, sum(R[a]["sess"][k][1] for R in Rs))
def fnum(x, d=2): return f"{x:.{d}f}".replace(".", ",")
def fsign(x, d=3): return ("+" if x >= 0 else "−") + fnum(abs(x), d)

def write_docx(path, items):
    """Мінімальний .docx без сторонніх бібліотек. items: ("h", текст) | ("p", текст) | ("t", head, rows, bold_rows, span_rows)."""
    def run(t, b=False, sz=18):
        return (f'<w:r><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>'
                f'{"<w:b/>" if b else ""}<w:sz w:val="{sz}"/></w:rPr><w:t xml:space="preserve">{escape(t)}</w:t></w:r>')
    def par(t, b=False, sz=24, jc="both", after=120, italic=False):
        r = run(t, b, sz).replace("<w:sz ", "<w:i/><w:sz ") if italic else run(t, b, sz)
        return f'<w:p><w:pPr><w:spacing w:after="{after}"/><w:jc w:val="{jc}"/></w:pPr>{r}</w:p>'
    body = []
    for it in items:
        if it[0] == "h": body.append(par(it[1], italic=True, jc="left", after=60))
        elif it[0] == "p": body.append(par(it[1], sz=20, after=240))
        else:
            _, head, rows, bold, spans = it[:5]; opt = it[5] if len(it) > 5 else {}
            n = len(head); W = 9072; w0 = opt.get("w0", 2600); wi = (W - w0) // (n - 1); ws = [w0] + [wi] * (n - 1)
            bd = "".join(f'<w:{x} w:val="single" w:sz="4" w:space="0" w:color="000000"/>' for x in ("top", "left", "bottom", "right", "insideH", "insideV"))
            x = [f'<w:tbl><w:tblPr><w:tblW w:w="{W}" w:type="dxa"/><w:tblBorders>{bd}</w:tblBorders>'
                 f'<w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>' + "".join(f'<w:gridCol w:w="{v}"/>' for v in ws) + "</w:tblGrid>"]
            def cell(t, w, b=False, span=1, jc="center"):
                gs = f'<w:gridSpan w:val="{span}"/>' if span > 1 else ""
                return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{gs}<w:vAlign w:val="center"/></w:tcPr>'
                        f'<w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="{jc}"/></w:pPr>{run(t, b)}</w:p></w:tc>')
            if "group" in opt:  # дворівнева шапка: [(текст, кількість колонок), ...] після першої колонки
                def vm(t, w, first):
                    v = '<w:vMerge w:val="restart"/>' if first else '<w:vMerge/>'
                    return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{v}<w:vAlign w:val="center"/></w:tcPr>'
                            f'<w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="center"/></w:pPr>{run(t, True) if first else ""}</w:p></w:tc>')
                x.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>' + vm(head[0], ws[0], True) +
                         "".join(cell(g, wi * k, True, k) for g, k in opt["group"]) + "</w:tr>")
                x.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>' + vm("", ws[0], False) +
                         "".join(cell(h, ws[i + 1], True) for i, h in enumerate(head[1:])) + "</w:tr>")
            else:
                x.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>' + "".join(cell(h, ws[i], True) for i, h in enumerate(head)) + "</w:tr>")
            for i, r in enumerate(rows):
                if i in spans: x.append("<w:tr>" + cell(r[0], W, False, n, "left").replace("<w:t ", "<w:t ") + "</w:tr>"); continue
                x.append("<w:tr>" + "".join(cell(v, ws[j], i in bold, 1, "left" if j == 0 else "center") for j, v in enumerate(r)) + "</w:tr>")
            x.append("</w:tbl>"); body.append("".join(x)); body.append(par("", sz=20, after=120))
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + "".join(body) +
           '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1417" w:right="1417" w:bottom="1417" w:left="1417" '
           'w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>')
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct); z.writestr("_rels/.rels", rels); z.writestr("word/document.xml", doc)

def write_csv(path, head, rows):
    """CSV для Excel з українськими налаштуваннями: роздільник «;», десяткова кома."""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";"); w.writerow(head); w.writerows(rows)

def mode_tables(quick=False, out_dir="results"):
    os.makedirs(out_dir, exist_ok=True)
    seeds = (401,) if quick else (401, 402, 403, 404, 405)
    sc = 0.2 if quick else 1.0
    a = 0.01
    M = article_methods()
    # ---- А. Основне порівняння (табл. 2) + показники в тексті
    res = defaultdict(list); ps = defaultdict(dict); uniq = []
    for i, sd in enumerate(seeds):
        log(f"[таблиці] основне порівняння: сід {sd} ({i+1}/{len(seeds)})"); raw = {}; cal, test = make_data(sd, scale=sc, raw=raw)
        gcal, gtest, gspec = lin_gated_data(sd, raw, 0.01, scale=sc)
        for n, sp in M.items():
            R = evaluate(gcal, gtest, gspec, sd, per_sess=True) if sp == "LIN_GATED" else evaluate(cal, test, sp, sd, per_sess=True)
            ps[n].update({(sd, k): v for k, v in R.pop("per_sess").items()}); res[n].append(R)
            if n == "Запропонований CTS": uniq.append(R["uniq"])
        res["Запропонований CTS, U = 1"].append(evaluate(cal, test, cts_final(), sd, U_fixed=1.0))
        res["Запропонований CTS, зважене калібрування"].append(evaluate(cal, test, cts_final(), sd, weighted=True))

    head2 = ["Метод", "FPR, %"] + [ATK_UA[k] for k in ATTACKS] + ["Середнє"]
    rows2, bold2, span2 = [], set(), set()
    def row2(n):
        fk, fn = agg_fpr(res[n], a); rec = [agg_rec(res[n], a, k) for k in ATTACKS]
        return [n, fnum(100 * fk / fn)] + [fnum(x) for x in rec] + [fnum(sum(rec) / len(rec), 3)]
    rows2.append(row2("Запропонований CTS")); bold2.add(0)
    span2.add(len(rows2)); rows2.append(["Абляції — варіанти запропонованого методу з вилученою однією складовою"])
    for n in ABLATIONS: rows2.append(row2(n))
    span2.add(len(rows2)); rows2.append(["Базові методи — інші підходи"])
    for n in list(M)[4:]: rows2.append(row2(n))
    # сесійний рівень
    head2s = ["Метод"] + [ATK_UA[k] for k in ATTACKS]
    rows2s = [[n] + [fnum(agg_sess(res[n], a, k)) for k in ATTACKS] for n in ("Запропонований CTS", LIN, "Новий ідентифікатор")]
    # показники для тексту
    fk, fn = agg_fpr(res["Запропонований CTS"], a); p, lo, hi = wilson(fk, fn)
    cls_all = sorted({c for R_ in res["Запропонований CTS"] for c in R_[a]["FPR_cls"]})
    fpr_cls = {c: [sum(R_[a]["FPR_cls"].get(c, [0, 0])[0] for R_ in res["Запропонований CTS"]),
                   sum(R_[a]["FPR_cls"].get(c, [0, 0])[1] for R_ in res["Запропонований CTS"])] for c in cls_all}
    fk5, fn5 = agg_fpr(res["Запропонований CTS"], 0.05)
    fku, fnu = agg_fpr(res["Запропонований CTS, U = 1"], a)
    mac = lambda n: sum(agg_rec(res[n], a, k) for k in ATTACKS) / len(ATTACKS)
    txt = [("FPR запропонованого CTS за α = 0,01, % [95 % ДІ Вільсона]", f"{fnum(100*p)} [{fnum(100*lo)}; {fnum(100*hi)}]"),
           ("FPR запропонованого CTS за α = 0,05, %", fnum(100 * fk5 / fn5)),
           ("FPR детермінованого варіанта (U = 1), α = 0,01, %", fnum(100 * fku / fnu)),
           ("Середня повнота: рандомізоване U / U = 1", f"{fnum(mac('Запропонований CTS'), 3)} / {fnum(mac('Запропонований CTS, U = 1'), 3)}"),
           ("Унікальних векторів ознак на сід (кеш оцінки d)", f"{min(uniq)}–{max(uniq)}"),
           ("FPR запропонованого CTS за класами операцій, α = 0,01, % [95 % ДІ Вільсона]",
            "; ".join(f"{c}: {fnum(100*wilson(*fpr_cls[c])[0])} [{fnum(100*wilson(*fpr_cls[c])[1])}; {fnum(100*wilson(*fpr_cls[c])[2])}]" for c in cls_all))]
    for n in ("Запропонований CTS", "Запропонований CTS, зважене калібрування"):
        ak, an = agg_fpr(res[n], a, "FPR"); rk, rn = agg_fpr(res[n], a)
        txt.append((f"{n}: FPR за теоремою 1 (по одному випадковому запиту кожного класу від користувача) / сукупна FPR за всіма легітимними запитами, %", f"{fnum(100*rk/rn)} / {fnum(100*ak/an)}"))

    for n in (LIN, "Новий ідентифікатор"):
        d = boot_diff(ps["Запропонований CTS"], ps[n], ATTACKS)
        txt.append((f"Різниця середньої повноти: CTS мінус «{n}» [95 % парний бутстреп-ДІ]", f"{fsign(d[0])} [{fsign(d[1])}; {fsign(d[2])}]"))
    # ---- Б. Мінливість FPR між калібруваннями
    log("[таблиці] мінливість FPR між калібруваннями")
    cal, test = make_data(401, scale=sc); f = []; fagg = []; reps = 5 if quick else 30
    for k in range(reps):
        R = evaluate(cal, test, cts_final(), 401, alphas=(a,), cal_seed=1000 + k)
        f.append(100 * R[a]["FPR_rand"][0] / R[a]["FPR_rand"][1]); fagg.append(100 * R[a]["FPR"][0] / R[a]["FPR"][1])
    f.sort(); mB = R["m"]
    fagg.sort()
    txt.append((f"FPR за α = 0,01 для {reps} незалежних калібрувань (за теоремою 1: запит класу k випадкового користувача), % (мін.–макс.; медіана)", f"{fnum(f[0])}–{fnum(f[-1])}; {fnum(f[len(f)//2])}"))
    txt.append((f"Сукупна FPR за всіма легітимними запитами для тих самих {reps} калібрувань, % (мін.–макс.; медіана)", f"{fnum(fagg[0])}–{fnum(fagg[-1])}; {fnum(fagg[len(fagg)//2])}"))
    txt.append(("Обсяг половини B за класами операцій", ", ".join(f"{k}: {v}" for k, v in sorted(mB.items()))))
    # ---- В. Чутливість до частки прямих посилань β
    rows_b = []
    for b_ in (0.0, 0.05, 0.10, 0.15):
        log(f"[таблиці] чутливість, β = {b_}"); raw = {}; cal, test = make_data(501, beta=b_, scale=sc, raw=raw)
        gcal, gtest, gspec = lin_gated_data(501, raw, 0.01, scale=sc, beta=b_)
        r = [fnum(b_)]
        for n in ("Запропонований CTS", LIN, "Новий ідентифікатор"):
            R = evaluate(gcal, gtest, gspec, 501, alphas=(a,)) if n == LIN else evaluate(cal, test, M[n], 501, alphas=(a,))
            r += [fnum(agg_rec([R], a, "guess")), fnum(agg_rec([R], a, "chain")), fnum(sum(agg_rec([R], a, k) for k in ATTACKS) / len(ATTACKS), 3)]
        rows_b.append(r)
    head_b = ["β", "CTS: вгад.", "CTS: ланцюг", "CTS: середнє", "Блок.: вгад.", "Блок.: ланцюг", "Блок.: середнє", "Новий ID: вгад.", "Новий ID: ланцюг", "Новий ID: середнє"]
    # ---- Д. Тихі ланцюги: перший запит атаки — відкриття чужого замовлення в темпі звичайної навігації.
    # Параметри зафіксовано до прогону: 20 % легітимних сесій починаються з прямого посилання на власне замовлення;
    # частка замовлень, ключі яких монітор уже бачив у межах L (оформлення, попередні списки), — 1,0 (реалістично за
    # великого L), 0,95, 0,8 і 0,5 (дедалі більше замовлень, оформлених поза полем зору монітора). Сід 701, α = 0,01.
    MQ = {"Запропонований CTS": M["Запропонований CTS"], "– без рекурсивної підтримки": M["– без рекурсивної підтримки"],
          LIN: "LIN_GATED", "Новий ідентифікатор": M["Новий ідентифікатор"]}
    rows_q, rows_qc = [], []; saved_q = dict(P)
    for seen_p in (1.0, 0.95, 0.8, 0.5):
        bo = seen_p
        log(f"[таблиці] тихі ланцюги, частка вже баченних замовлень = {seen_p}")
        P.update(saved_q); P.update(beta_open=0.2, order_seen_prob=seen_p)
        atk_q = ATTACKS + ATTACKS_QUIET
        raw = {}; cal, test = make_data(701, scale=sc, attacks=atk_q, raw=raw)
        gcal, gtest, gspec = lin_gated_data(701, raw, 0.01, scale=sc)
        r1 = [fnum(bo)]; r2 = [fnum(bo)]
        for n, sp in MQ.items():
            if sp == "LIN_GATED": R = evaluate(gcal, gtest, gspec, 701, alphas=(a,), attacks=atk_q, return_pv=True); T = gtest
            else: R = evaluate(cal, test, sp, 701, alphas=(a,), attacks=atk_q, return_pv=True); T = test
            fk, fn = R[a]["FPR_rand"]
            r1 += [fnum(100 * fk / fn)] + [fnum(R[a]["rec"][k][0] / max(1, R[a]["rec"][k][1])) for k in ATTACKS_QUIET]
            for k in ATTACKS_QUIET:
                sh, rc, nq = quiet_chain_stats(T, R["pv"], a, k)
                r2 += [fnum(sh), fnum(rc) if nq else "—"]
        rows_q.append(r1); rows_qc.append(r2)
    P.clear(); P.update(saved_q)
    mq_short = {"Запропонований CTS": "CTS", "– без рекурсивної підтримки": "без рекурсії", LIN: "блок.", "Новий ідентифікатор": "новий ID"}
    head_q = ["Частка баченних замовлень"] + [f"{mq_short[n]}: {x}" for n in MQ for x in ("FPR, %", "ланцюг 1", "ланцюг 3")]
    head_qc = ["Частка баченних замовлень"] + [f"{mq_short[n]}, {ATK_UA[k][-15:]}: {x}" for n in MQ for k in ATTACKS_QUIET for x in ("частка без сигналу на 1-му запиті", "повнота далі")]
    # ---- Г. Стрес-перевірка (табл. 3) і нові атаки
    scen = {"S0 базові параметри": {}, "S1 довгі сесії (10–40 дій)": dict(actions_per_session=(10, 40)),
            "S2 короткі сесії (2–6 дій)": dict(actions_per_session=(2, 6)), "S3 частка спільних документів 0,3": dict(share_prob=0.3),
            "S4 швидкий легітимний темп (3 с)": dict(gap_mean=3.0), "S5 повільний легітимний темп (30 с)": dict(gap_mean=30.0),
            "S6 повільніший перебір (5–15 хв)": dict(slow_gap=(300, 900)), "S7 3–6 сесій на добу": dict(sessions_per_user=(3, 6)),
            "S8 частка прямих посилань 0,10": dict(beta=0.10)}
    MS = {k: M[k] for k in ("Запропонований CTS", LIN, "Новий ідентифікатор")}
    saved = dict(P); rows3, rows3a, rows3b = [], [], []
    for name, ch in scen.items():
        log(f"[таблиці] стрес-перевірка: {name}")
        P.update(saved); P.update(write_prob=0.1); P.update(ch)
        rs = defaultdict(list)
        for sd in ((601,) if quick else (601, 602)):
            raw = {}; cal, test = make_data(sd, scale=0.6 * sc, attacks=ATTACKS_ALL, raw=raw)
            gcal, gtest, gspec = lin_gated_data(sd, raw, 0.01, scale=0.6 * sc)
            for n, sp in MS.items():
                rs[n].append(evaluate(gcal, gtest, gspec, sd, alphas=(a,), attacks=ATTACKS_ALL) if sp == "LIN_GATED"
                             else evaluate(cal, test, sp, sd, alphas=(a,), attacks=ATTACKS_ALL))
        m3 = lambda n: sum(agg_rec(rs[n], a, k) for k in ATTACKS_ALL) / len(ATTACKS_ALL)
        fk, fn = agg_fpr(rs["Запропонований CTS"], a)
        m5 = lambda n: sum(agg_rec(rs[n], a, k) for k in ATTACKS) / len(ATTACKS)
        rows3.append([name, fnum(m3("Запропонований CTS"), 3), fnum(100 * fk / fn), fnum(m3(LIN), 3), fnum(m3("Новий ідентифікатор"), 3)])
        rows3b.append([name] + [fnum(m5(n), 3) for n in MS])
        rows3a.append([name] + [fnum(agg_rec(rs[n], a, k)) for k in ATTACKS_NEW for n in ("Запропонований CTS", LIN, "Новий ідентифікатор")])
    P.clear(); P.update(saved)
    head3 = ["Сценарій", "Запропонований CTS", "FPR CTS, %", "Блокування за сигналом", "Новий ідентифікатор"]
    head3a = ["Сценарій"] + [f"{ATK_UA[k]}: {m}" for k in ATTACKS_NEW for m in ("CTS", "блок.", "новий ID")]
    # ---- запис
    n_s = len(seeds)
    T2 = f"Таблиця 2 — Частка виявлених запитів атаки за α = 0,01: запропонований метод, його абляції та базові методи (синтетичні дані, сідів: {n_s})"
    T3 = f"Таблиця 3 — Стрес-перевірка: середня повнота за вісьмома типами атак (α = 0,01, сідів: {1 if quick else 2})"
    items = [("h", T2), ("t", head2, rows2, bold2, span2, dict(w0=2400)),
             ("h", "Додаткова таблиця А — Частка виявлених атакувальних сесій за α = 0,01"), ("t", head2s, rows2s, set(), set()),
             ("h", T3), ("t", head3, rows3, set(), set(), dict(w0=3200)),
             ("h", "Додаткова таблиця Б — Повнота для нових атак у стрес-сценаріях (α = 0,01)"), ("t", ["Сценарій"] + ["CTS", "Блок.", "Нов. ID"] * 3, rows3a, set(), set(),
              dict(w0=2800, group=[(ATK_UA[k], 3) for k in ATTACKS_NEW])),
             ("h", "Додаткова таблиця Б2 — Стрес-сценарії: середня повнота за п'ятьма типами атак табл. 2 (для зіставлення з табл. 2)"),
             ("t", ["Сценарій", "CTS", "Блок.", "Новий ID"], rows3b, set(), set(), dict(w0=3600)),
             ("h", "Додаткова таблиця В — Чутливість до частки законних прямих посилань β (сід 501, α = 0,01)"), ("t", head_b, rows_b, set(), set(), dict(w0=1200)),
             ("h", "Додаткова таблиця Д1 — Тихі ланцюги: FPR і повнота залежно від частки замовлень, ключі яких монітор уже бачив у межах L (20 % сесій починаються з прямого посилання; сід 701, α = 0,01)"), ("t", head_q, rows_q, set(), set(), dict(w0=900)),
             ("h", "Додаткова таблиця Д2 — Тихі ланцюги: частка ланцюгів без сигналу на першому запиті й повнота на подальших запитах у таких ланцюгах"),
             ("t", head_qc, rows_qc, set(), set(), dict(w0=900)),
             ("h", "Числа, що наводяться в тексті статті"), ("t", ["Показник", "Значення"], [list(x) for x in txt], set(), set(), dict(w0=6000))]
    if quick: items.insert(0, ("p", "УВАГА: швидкий прогін на малому обсязі даних — числа не для статті."))
    items.append(("p", "Дані синтетичні. Мітки порушень беруться з ACL моделі й використовуються тільки для оцінювання. "
                       "Сценарій S6 у статті не наведено, бо його результати збігаються з базовим S0."))
    write_docx(os.path.join(out_dir, "tables.docx"), items)
    write_csv(os.path.join(out_dir, "table2.csv"), head2, [r if len(r) > 1 else r + [""] * (len(head2) - 1) for r in rows2])
    write_csv(os.path.join(out_dir, "table2_sessions.csv"), head2s, rows2s)
    write_csv(os.path.join(out_dir, "table3_stress.csv"), head3, rows3)
    write_csv(os.path.join(out_dir, "table3_new_attacks.csv"), head3a, rows3a)
    write_csv(os.path.join(out_dir, "table3_mean5.csv"), ["Сценарій", "CTS: середнє за 5 типами", "Блок.: середнє за 5 типами", "Новий ID: середнє за 5 типами"], rows3b)
    write_csv(os.path.join(out_dir, "sensitivity_beta.csv"), head_b, rows_b)
    write_csv(os.path.join(out_dir, "text_numbers.csv"), ["Показник", "Значення"], txt)
    write_csv(os.path.join(out_dir, "quiet_chains.csv"), head_q, rows_q)
    write_csv(os.path.join(out_dir, "quiet_chains_cond.csv"), head_qc, rows_qc)
    log(f"\nГотово. Таблиці записано в {out_dir}/tables.docx і {out_dir}/*.csv")
    for t_, h_, r_ in ((T2, head2, rows2), (T3, head3, rows3)):
        log("\n" + t_); log(" | ".join(h_)); [log(" | ".join(x)) for x in r_]
    log("\nЧисла для тексту:"); [log(f"  {k}: {v}") for k, v in txt]


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__); sys.exit(0)
    log("Імітаційна модель CTS. Дані синтетичні. Повний прогін триває кілька хвилин.")
    if "--tables" in sys.argv:
        mode_tables(quick="--quick" in sys.argv)
    elif "--article" in sys.argv:
        mode_article()
    elif "--fixes" in sys.argv:
        mode_fixes()
    elif "--quick" in sys.argv:
        cal, test = make_data(1, scale=0.2)
        res = {n: [evaluate(cal, test, sp, 1)] for n, sp in baselines().items()}
        table(res, 0.01, "ШВИДКИЙ ПРОГІН (малий обсяг, лише для перевірки роботи скрипта)")
    else:
        name, params = mode_search()
        log(f"\nОбраний варіант (на сідах розробки): {name}")
        mode_final(params)
        mode_sens(params)
    log("\nГотово. Результати також збережено у файлах *.json поруч зі скриптом.")
