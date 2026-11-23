# CTS-BOLA: simulation code

Simulation code for the paper:

> Ustymenko M. S. *Method for detecting signs of BOLA/IDOR in REST APIs based on dynamic context-graph session analysis* (in Ukrainian: «Метод виявлення ознак BOLA/IDOR у REST API на основі динамічного контекстно-графового аналізу сесій»). Submitted to *Technical Sciences and Technologies*, 2026.

The script reproduces **all tables and numbers** of the paper's experimental section. The data are **fully synthetic**: no real users, traffic or vulnerabilities are involved.

## What the method does

A passive monitor at the API gateway sees request–response pairs but not the access policy. The method:

1. **Recursive identifier provenance.** An object key is *supported* only if the user received it from a chain of responses that starts at a *root* operation (one with no client-supplied object key, e.g. `GET /me/orders`). Trust is propagated only through responses to supported events, so a chain started from a guessed foreign key gets no trust (Theorem 2 in the paper).
2. **Context level and enumeration counters.** The context level `c ∈ {0, 1, 2}` is combined with the number of distinct weakly supported objects accessed in the last 10 s and 24 h.
3. **Conformal CTS score.** The features are aggregated by a dominance rule and calibrated as a conformal p-value per operation class, with calibration units = users. The false-alarm probability for a random request of a random legitimate user is then at most α (Theorem 1).

## Requirements

- Python **3.8+**
- No third-party packages; only the standard library is used.

## Quick start

```bash
# all tables and numbers of the paper (~30 min on a typical laptop)
python cts_sim.py --tables

# fast smoke test on a small dataset (~1–2 min); numbers are NOT for the paper
python cts_sim.py --tables --quick
```

On **Windows**, run it from PowerShell. To keep a readable log:

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
python -X utf8 cts_sim.py --tables 2>&1 | Tee-Object -FilePath run_log.txt
```

`--quick` writes to the same `results/` folder, so run the full mode afterwards.

## Output (`results/`)

| File | Content |
|---|---|
| `tables.docx` | All tables in one Word document |
| `table2.csv` | Main comparison (Table 2): FPR and recall per attack type; the method, its ablations and the baselines; 5 seeds |
| `table2_sessions.csv` | Share of detected attacker sessions |
| `table3_stress.csv` | Stress test (Table 3): mean recall over 8 attack types in 9 scenarios |
| `table3_new_attacks.csv` | Recall for the three stress-only attacks |
| `table3_mean5.csv` | Stress scenarios, mean recall over the 5 attack types of Table 2 |
| `sensitivity_beta.csv` | Sensitivity to the share of legitimate direct links β |
| `quiet_chains.csv` | "Quiet" chains: FPR and recall vs. the share of orders whose keys the monitor has already seen |
| `quiet_chains_cond.csv` | Quiet chains: share of chains whose first request got no signal, and recall on the rest of such chains |
| `text_numbers.csv` | All numbers quoted in the text (FPR with Wilson intervals, per-class FPR, bootstrap intervals, 30 calibrations, etc.) |

CSV files use `;` as the separator and a decimal comma, so they open directly in Excel with Ukrainian locale settings.

## Model and experiment (short)

- **Application model.** Each user has 2–6 orders with 1–4 documents; 10 % of documents are shared with another user; sessions have 4–15 actions (list, open order, read documents); 5 % of reads use a direct link without prior navigation. H = 60 s, L = 24 h, one-day history.
- **Attacks.** 100 attackers per type: guessing, fast and slow enumeration, chained access to foreign orders, leak through an over-exposing root list (violation of assumption A1). The stress test adds interleaved enumeration, cautious reading and BOLA on writes (PATCH). An extra experiment adds quiet chains, where legitimate users sometimes open their own order via a direct link.
- **Calibration and test.** 3000 calibration users (halves A and B by users) and 2000 legitimate test users plus 500 attackers, 5 seeds. FPR is measured as in Theorem 1: one random request of each operation class per legitimate user.
- **Baselines** are the author's own constructions, evaluated under the same conditions and calibration: signal-gated evidence blocking without recursion, the new-identifier rule, distinct objects per session, request rate in 10 s. The published methods discussed in the paper are not re-implemented (see the paper for the reasons).
- **True permissions** come from the model's ACL and are used **only for evaluation**; the method never sees them.

Other modes (`--article`, `--fixes`, default search over 74 configurations) were used during development. They are kept for transparency and are not needed to reproduce the paper.

## Reproducibility

All random generators are seeded (main comparison: seeds 401–405; calibration variability: 401; β sensitivity: 501; stress test: 601–602; quiet chains: 701), so the same script should give the same numbers on any machine with the same Python version. The configuration was chosen on separate development seeds before the final runs.

## Limitations

The results describe a synthetic test bed with one application type and one day of history. They are not estimates for production APIs. See the "Limitations" part of the paper.

## Citation

If you use this code, please cite the paper (details will be added after publication) and this repository:

```
Ustymenko M. S. CTS-BOLA: simulation code. 2026. URL: https://github.com/MaxUstymenko/cts-bola-simulation
```

## License

MIT — see `LICENSE`.
