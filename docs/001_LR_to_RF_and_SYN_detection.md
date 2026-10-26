# Cambio 001 — Logistic Regression → Random Forest + Detección SYN Flood

**Fecha:** 2026-08-21  
**Solicitado por:** Usuario  

---

## Motivación

1. **SYN Flood no detectado:** La corrida anterior con Logistic Regression clasificó los flujos TCP SYN flood como benignos (P_attack < 0.5) porque `down_up_ratio ≈ 0` (sin servidor respondiendo en h15) y el modelo lineal no podía capturar la interacción no lineal entre `syn_flag_cnt`, `protocol=6` y `fwd_pkts_s`.
2. **Limitaciones de LR:** Logistic Regression es un clasificador lineal que no puede modelar fronteras de decisión complejas. Random Forest captura interacciones entre features y es más robusto ante distribución sesgada.

---

## Cambios realizados

### 1. `retrain_model_for_ryu.py`

| Aspecto | Antes (LR) | Después (RF) |
|---------|-----------|-------------|
| Clasificador | `LogisticRegression(max_iter=2000, class_weight="balanced")` | `RandomForestClassifier(n_estimators=200, max_depth=20, min_samples_leaf=5, class_weight="balanced")` |
| Modelo exportado | `ryu_lr_model.pkl` | `ryu_rf_model.pkl` |
| Métricas extra | Coeficientes lineales | Feature importances (Gini), confusion matrix, latencia predicción |
| Tiempo entrenamiento | ~2s | ~40s |

**Resultados RF en test set (30%):**

| Métrica | Valor |
|---------|-------|
| Accuracy | 99.75% |
| Precision (ataque) | 99.95% |
| Recall (ataque) | 99.76% |
| F1-Score | 99.75% |
| TN / FP | 13224 / 36 |
| FN / TP | 163 / 67244 |

**Feature importances (Gini):**

| Feature | Importancia |
|---------|------------|
| fwd_pkt_len_max | 0.2785 |
| pkt_len_min | 0.1514 |
| fwd_pkts_s | 0.1248 |
| flow_pkts_s | 0.1188 |
| rst_flag_cnt | 0.0859 |
| down_up_ratio | 0.0773 |
| fwd_psh_flags | 0.0507 |
| bwd_pkt_len_min | 0.0389 |
| bwd_pkts_s | 0.0285 |
| syn_flag_cnt | 0.0228 |
| protocol | 0.0225 |

### 2. `ryu_ddos_ml.py`

- **Carga modelo:** Cambiado de `ryu_lr_model.pkl` a `ryu_rf_model.pkl`.
- **Heurística SYN flood:** Si el modelo RF no clasifica como ataque (`prediction=0`) pero se cumplen:
  - `proto == 6` (TCP)
  - `p_attack >= 0.3`
  - `fwd_p > 50` paquetes
  - `raw_syn > 10` (SYN flags observados en packet-in)
  - `down_up_ratio < 0.1` (sin respuesta del servidor)
  
  → Se fuerza `is_attack = True` y se loguea como `SYN-heuristic triggered`.

### 3. `simulacion_mininet.py`

- **Servidor HTTP en h15:** Se lanza `python3 -m http.server 80` en la víctima (h15) **antes** de iniciar ataques. Esto genera tráfico SYN-ACK de respuesta, haciendo que `down_up_ratio > 0` para los flujos TCP, lo cual permite al modelo RF detectar mejor el patrón de SYN flood.

---

## Archivos de backup

| Archivo | Descripción |
|---------|-------------|
| `CHANGES/retrain_model_for_ryu_LR_backup.py` | Script de reentrenamiento con LR |
| `CHANGES/ryu_ddos_ml_LR_backup.py` | Controlador Ryu con LR |
| `CHANGES/simulacion_mininet_LR_backup.py` | Simulación sin HTTP server |
| `CHANGES/detecciones_ryu_LR_lastrun.csv` | Detecciones de la última corrida LR |
| `CHANGES/ryu_controller_LR_lastrun.log` | Log del controlador última corrida LR |

---

## Impacto esperado

- UDP flood, ICMP flood: detección similar o mejor (RF generaliza bien).
- SYN flood: detección mejorada por (a) servidor HTTP generando respuestas, (b) modelo no lineal capturando interacciones, (c) heurística de respaldo para flujos con alta tasa SYN sin respuesta.
- Slow-rate: detección dependiente del volumen; RF puede capturar patrones sutiles que LR no podía.
