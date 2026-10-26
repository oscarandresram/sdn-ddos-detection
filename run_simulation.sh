#!/bin/bash

# Limpieza inicial
echo "Limpiando entorno previo de Mininet..."
sudo mn -c > /dev/null 2>&1
sudo pkill -f ryu-manager
sleep 2
CONTROLLER_LOG="./ryu_controller.log"
echo "=========================================="
echo "Iniciando Controlador ML Ryu SDN"
echo "=========================================="

# Ejecuta el controlador ryu usando la ruta directa del virtualenv ryu-py310
# Esto evita problemas de activación en scripts no interactivos
RYU_BIN="${RYU_BIN:-ryu-manager}"

if [ ! -f "$RYU_BIN" ]; then
    echo "¡ADVERTENCIA! No se encontró $RYU_BIN."
    echo "Asegúrate de que ryu-manager esté instalado en el entorno ryu-py310."
    # Fallback to system ryu-manager
    RYU_BIN="ryu-manager"
fi

$RYU_BIN "./ryu_ddos_ml.py" > "$CONTROLLER_LOG" 2>&1 &
RYU_PID=$!

echo "Controlador Ryu iniciado en background (PID: $RYU_PID)."
echo "El registro del controlador se está guardando en: $CONTROLLER_LOG"
echo "Esperando 5 segundos para asegurar que el controlador arranque..."
sleep 5

echo "=========================================="
echo "Iniciando Simulación Mininet"
echo "=========================================="
echo "** PREGUNTARÁ POR TU CONTRASEÑA DE SUDO **"
sudo python3 "./simulacion_mininet.py"

echo "=========================================="
echo "Simulación Finalizada"
echo "=========================================="

echo "Deteniendo Controlador Ryu..."
sudo kill $RYU_PID
sudo pkill -f ryu-manager

echo "=========================================="
echo "Archivos generados:"
echo "- ./captura_simulacion.pcap (Captura raw)"
echo "- ./detecciones_ryu.csv (Registro de Detecciones ML)"
echo "- $CONTROLLER_LOG (Log completo del controlador)"
echo "=========================================="
