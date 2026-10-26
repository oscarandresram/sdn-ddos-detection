import os
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else "."
file_path = os.path.join(base_dir, "adddosdn_cicflow_dataset.csv")
print(f"Cargando dataset desde: {file_path}")

df = pd.read_csv(file_path)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

ryu_features = [
    "down_up_ratio",
    "flow_pkts_s",
    "rst_flag_cnt",
    "pkt_len_min",
    "bwd_pkts_s",
    "fwd_pkts_s",
    "bwd_pkt_len_min",
    "fwd_pkt_len_max",
    "syn_flag_cnt",
    "fwd_psh_flags",
    "protocol",
]

missing = [f for f in ryu_features if f not in df.columns]
if missing:
    raise SystemExit(f"Features ausentes: {missing}")

X = df[ryu_features]
y = df["Label_binary"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

print(f"Entrenando Random Forest con {len(ryu_features)} features (balanced).")
print("Features:", ryu_features)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

t0 = time.time()
model_rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=5,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced",
)
model_rf.fit(X_train_scaled, y_train)
train_time = time.time() - t0

y_pred = model_rf.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="weighted")
rec = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")
rec_att = recall_score(y_test, y_pred, pos_label=1)
prec_att = precision_score(y_test, y_pred, pos_label=1)

print(f"\nTiempo entrenamiento: {train_time:.2f}s")
print("\n" + "=" * 50)
print("RESULTADOS Random Forest RYU (11 features)")
print("=" * 50)
print(f"Accuracy  : {acc:.4f} ({acc * 100:.2f}%)")
print(f"Precision : {prec:.4f} ({prec * 100:.2f}%)")
print(f"Recall    : {rec:.4f} ({rec * 100:.2f}%)")
print(f"F1-Score  : {f1:.4f} ({f1 * 100:.2f}%)")
print(f"Recall ataque (pos=1): {rec_att:.4f}")
print(f"Precision ataque     : {prec_att:.4f}")
print("=" * 50)
print(classification_report(y_test, y_pred, target_names=["normal", "ataque"]))
print("Confusion matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN={cm[0,0]:6d}  FP={cm[0,1]:5d}")
print(f"  FN={cm[1,0]:6d}  TP={cm[1,1]:5d}")

print("\nFeature importances (Gini):")
for name, imp in sorted(zip(ryu_features, model_rf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {name:20s} {imp:.4f}")

t_pred = time.time()
_ = model_rf.predict(X_test_scaled[:100])
pred_ms = (time.time() - t_pred) * 1000 / 100
print(f"\nLatencia prediccion batch-1 estimada: {pred_ms:.3f} ms")

model_filename = os.path.join(base_dir, "ryu_rf_model.pkl")
scaler_filename = os.path.join(base_dir, "ryu_scaler.pkl")
joblib.dump(model_rf, model_filename)
joblib.dump(scaler, scaler_filename)
joblib.dump(ryu_features, os.path.join(base_dir, "ryu_features.pkl"))

print(f"\nModelo exportado en: {model_filename}")
print(f"Scaler exportado en: {scaler_filename}")
