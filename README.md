# Detección de DDoS en redes SDN

Código del trabajo de grado de Oscar Andrés Ramírez Balcázar, estudiante de Ingeniería Electrónica y Telecomunicaciones en la Universidad del Cauca (grado previsto para mediados de 2027). Borrador más completo: septiembre de 2026.

El problema es si un modelo entrenado con datos de laboratorio sigue sirviendo cuando corre dentro de un controlador SDN, usando solo medidas que OpenFlow 1.3 puede entregar.

## Qué hay aquí

| Archivo | Qué hace |
| --- | --- |
| `feature_selection_extratrees.py` | Selecciona variables con Extra Trees e importancia de Gini, un ataque contra tráfico normal, y se queda con las que acumulan cerca del 90 % de la importancia. Separa las que el controlador puede leer en OpenFlow. |
| `feature_selection_extratrees_results.json` | Resultado de esa selección sobre AdDDoSDN (268.887 filas). |
| `retrain_model_for_ryu.py` | Entrena un Random Forest (`n_estimators=200`, `max_depth=20`, `class_weight="balanced"`) con 11 variables. El `StandardScaler` se ajusta solo con el conjunto de entrenamiento. Guarda el modelo y el escalador con joblib. |
| `ryu_ddos_ml.py` | Controlador Ryu (OpenFlow 1.3) que carga el modelo y clasifica flujos en vivo. |
| `simulacion_mininet.py` | Red Mininet de 5 conmutadores. Lanza inundaciones UDP, TCP SYN, ICMP y un ataque de baja tasa. |
| `run_simulation.sh` | Arranca el controlador y después la simulación. |
| `test_port.py` | Comprueba si el puerto 6653 del controlador responde. |
| `docs/001_LR_to_RF_and_SYN_detection.md` | Por qué se pasó de regresión logística a Random Forest: el modelo lineal no veía el SYN flood. |

## Qué no está incluido

El archivo `adddosdn_cicflow_dataset.csv` (AdDDoSDN, derivado de CICFlowMeter) no se publica aquí por su tamaño. Sin ese archivo, `feature_selection_extratrees.py` y `retrain_model_for_ryu.py` no pueden reentrenar. Los modelos `ryu_rf_model.pkl` y `ryu_scaler.pkl` tampoco van en el repositorio: los genera el entrenamiento. InSDN se usó en el mismo trabajo y tampoco se incluye.

La exactitud fuera de línea, con las 11 variables, supera el 99,7 %. Esa cifra no se mantiene en la red emulada: las inundaciones de alto volumen se detectan y el ataque de baja tasa no. Las unidades del entrenamiento y los contadores OpenFlow no coinciden.

## Cómo ejecutarlo

Hace falta Python 3, Mininet, Open vSwitch y Ryu, además de:

```bash
pip install -r requirements.txt
```

Con el CSV de AdDDoSDN en este directorio:

```bash
python3 feature_selection_extratrees.py
python3 retrain_model_for_ryu.py
./run_simulation.sh
```

`run_simulation.sh` usa `ryu-manager` del PATH. En la máquina de desarrollo apuntaba a un entorno local de pyenv.
