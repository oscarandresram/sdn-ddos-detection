#!/usr/bin/env python3
"""Extra Trees (Gini) feature selection, one-vs-normal per Attack_Type."""

import json
import os
import time
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier

BASE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE, "adddosdn_cicflow_dataset.csv")
OUT_JSON = os.path.join(BASE, "feature_selection_extratrees_results.json")

ID_COLS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "timestamp",
    "Label_binary", "Label_multi", "Attack_Type",
}
# Unnamed index from CICFlowMeter export
DROP_PREFIXES = ("Unnamed",)

# Directly computable from OpenFlow FlowStats (duration, pkt/byte counts, ip_proto).
OPENFLOW_DIRECT = {
    "protocol",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "fwd_pkts_s",
    "bwd_pkts_s",
    "flow_pkts_s",
    "flow_byts_s",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "pkt_len_mean",
    "pkt_size_avg",
    "fwd_seg_size_avg",
    "bwd_seg_size_avg",
    "down_up_ratio",
    "subflow_fwd_pkts",
    "subflow_bwd_pkts",
    "subflow_fwd_byts",
    "subflow_bwd_byts",
}

# Approximable in Ryu: TCP flag matches, mean packet size (not min/max/std of IAT).
OPENFLOW_APPROX = {
    "syn_flag_cnt",
    "ack_flag_cnt",
    "fin_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "urg_flag_cnt",
    "ece_flag_cnt",
    "cwr_flag_count",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "pkt_len_max",
    "pkt_len_min",
    "fwd_act_data_pkts",
}


def extractability(name: str) -> str:
    if name in OPENFLOW_DIRECT:
        return "openflow_direct"
    if name in OPENFLOW_APPROX:
        return "openflow_approx"
    return "not_extractable"


def cumulative_90(names, importances):
    order = np.argsort(importances)[::-1]
    cum = 0.0
    selected = []
    for i in order:
        cum += float(importances[i])
        selected.append((names[i], float(importances[i]), cum))
        if cum >= 0.90:
            break
    return selected


def main():
    t0 = time.time()
    print(f"Cargando {CSV_PATH} ...")
    df = pd.read_csv(CSV_PATH)
    print(f"Filas={len(df)} cols={len(df.columns)}")

    feat_cols = [
        c for c in df.columns
        if c not in ID_COLS and not str(c).startswith(DROP_PREFIXES)
    ]
    # keep numeric only
    numeric = df[feat_cols].apply(pd.to_numeric, errors="coerce")
    df[feat_cols] = numeric

    counts = df["Attack_Type"].value_counts().to_dict()
    attacks = [a for a in df["Attack_Type"].unique() if a != "normal"]
    attacks = sorted(attacks, key=lambda a: -counts.get(a, 0))

    benign = df[df["Attack_Type"] == "normal"].copy()
    print(f"Features numéricas={len(feat_cols)}  benigno={len(benign)}  ataques={attacks}")

    per_attack = {}
    importance_matrix = defaultdict(dict)  # feat -> attack -> importance

    for attack in attacks:
        mal = df[df["Attack_Type"] == attack]
        sub = pd.concat([benign, mal], axis=0)
        X = sub[feat_cols].replace([np.inf, -np.inf], np.nan)
        mask = X.notna().all(axis=1)
        X = X.loc[mask]
        y = (sub.loc[mask, "Attack_Type"] == attack).astype(int)

        print(f"\n=== {attack} vs normal  n={len(X)}  pos={int(y.sum())} ===")
        t_fit = time.time()
        clf = ExtraTreesClassifier(
            n_estimators=100, n_jobs=-1, random_state=42
        )
        clf.fit(X.values, y.values)
        imps = clf.feature_importances_
        elapsed = time.time() - t_fit

        ranking = [
            {"feature": feat_cols[i], "importance": float(imps[i]),
             "extractability": extractability(feat_cols[i])}
            for i in np.argsort(imps)[::-1]
        ]
        sel90 = cumulative_90(feat_cols, imps)
        print(f"  fit={elapsed:.1f}s  n_90={len(sel90)}  top1={sel90[0][0]}={sel90[0][1]:.4f}")

        for f, imp, _ in sel90:
            importance_matrix[f][attack] = imp

        per_attack[attack] = {
            "n_rows": int(len(X)),
            "n_attack": int(y.sum()),
            "n_benign": int((y == 0).sum()),
            "fit_seconds": round(elapsed, 2),
            "n_features_90": len(sel90),
            "features_90": [
                {
                    "feature": f,
                    "importance": round(imp, 6),
                    "cum_importance": round(cum, 6),
                    "extractability": extractability(f),
                }
                for f, imp, cum in sel90
            ],
            "ranking_top20": ranking[:20],
        }

    n_attacks = len(attacks)
    scored = []
    for feat, by_atk in importance_matrix.items():
        # mean over ALL attacks (missing = 0)
        mean_imp = sum(by_atk.get(a, 0.0) for a in attacks) / n_attacks
        n_present = sum(1 for a in attacks if a in by_atk)
        scored.append({
            "feature": feat,
            "mean_importance": mean_imp,
            "n_attacks_in_90": n_present,
            "in_all_attacks": n_present == n_attacks,
            "extractability": extractability(feat),
            "per_attack": {a: round(by_atk.get(a, 0.0), 6) for a in attacks},
        })
    scored.sort(key=lambda x: (-x["n_attacks_in_90"], -x["mean_importance"]))

    # Prefer extractable; require presence in >=2 attack 90% sets.
    common = []
    seen = set()

    def take(pool, pred):
        for item in pool:
            if item["feature"] in seen:
                continue
            if not pred(item):
                continue
            common.append(item)
            seen.add(item["feature"])
            if len(common) >= 10:
                return True
        return False

    extractable = lambda x: x["extractability"] in ("openflow_direct", "openflow_approx")
    ge2 = lambda x: x["n_attacks_in_90"] >= 2

    take(scored, lambda x: extractable(x) and x["in_all_attacks"])
    take(scored, lambda x: extractable(x) and ge2(x))
    take(scored, lambda x: extractable(x))
    take(scored, ge2)
    take(scored, lambda x: True)

    common10 = common[:10]
    print("\n=== 10 comunes ===")
    for i, c in enumerate(common10, 1):
        print(f"{i:2d}. {c['feature']:24s}  mean={c['mean_importance']:.4f}  "
              f"in_90={c['n_attacks_in_90']}/{n_attacks}  {c['extractability']}")

    out = {
        "n_rows": int(len(df)),
        "n_numeric_features": len(feat_cols),
        "attack_counts": counts,
        "attacks": attacks,
        "method": "ExtraTreesClassifier n_estimators=100 Gini OvR vs normal",
        "per_attack": per_attack,
        "common10": [
            {
                **{k: v for k, v in c.items() if k != "per_attack"},
                "mean_importance": round(c["mean_importance"], 6),
                "per_attack": c["per_attack"],
            }
            for c in common10
        ],
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    with open(OUT_JSON, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nEscrito {OUT_JSON}  total={out['elapsed_seconds']}s")


if __name__ == "__main__":
    main()
