import time
import os
import atexit
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import LinearTopo
from functools import partial
from mininet.cli import CLI
from mininet.log import setLogLevel, info

_stopped = False

def stop_all(net):
    global _stopped
    if _stopped:
        return
    _stopped = True
    info("*** Deteniendo simulación...\\n")
    try:
        if net:
            net.stop()
    except Exception:
        pass
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -f tcpdump')
    os.system('sudo pkill -f iperf')
    os.system('sudo pkill -f hping3')

def start_simulation():
    setLogLevel('info')

    # Limpieza previa (removido sudo mn -c para no matar a ryu-manager que fue lanzado externamente)
    pass
    
    info("*** Configurando topología: 5 switches, 3 hosts por switch (Linear)\\n")
    # LinearTopo(k=5, n=3) -> 5 switches (s1..s5), 15 hosts total (h1..h15)
    topo = LinearTopo(k=5, n=3)
    
    # Configurar switch para usar explicitamente OpenFlow1.3 (requerido por las reglas Ryu OF1.3)
    switch = partial(OVSSwitch, protocols='OpenFlow13')
    
    # Iniciar Mininet apuntando al controlador remoto por defecto (c0, 127.0.0.1, 6653)
    net = Mininet(topo=topo, controller=RemoteController, switch=switch, waitConnected=True)
    
    # Asegurar limpieza al salir
    atexit.register(stop_all, net)

    info("*** Iniciando red\\n")
    net.start()

    info("*** Desactivando offloads TSO/GSO/GRO (pkt_len alineado a CICFlowMeter)\\n")
    for node in list(net.hosts) + list(net.switches):
        for intf in node.intfList():
            if intf.name and intf.name != "lo":
                node.cmd(f"ethtool -K {intf.name} gro off gso off tso off tx off 2>/dev/null")

    # Dar tiempo a que los switches se conecten al controlador y negocien
    info("*** Esperando 5s para negociacion OpenFlow...\\n")
    time.sleep(5)

    hosts = net.hosts
    h1, h2, h3 = hosts[0], hosts[1], hosts[2]
    h4, h5, h6, h7 = hosts[3], hosts[4], hosts[5], hosts[6]
    h13, h14, h15 = hosts[12], hosts[13], hosts[14]

    # Servidor HTTP en h15 (víctima) para que SYN floods generen SYN-ACK (down_up_ratio>0)
    info("*** Iniciando servidor HTTP en h15:80 para tráfico bidireccional SYN...\n")
    h15.cmd('python3 -m http.server 80 > /dev/null 2>&1 &')

    # Iniciar captura de PCAP en la victima
    info("*** Iniciando captura PCAP en h15...\\n")
    base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else '.'
    pcap_path = os.path.join(base_dir, 'captura_simulacion.pcap')
    h15.cmd(f'tcpdump -i {h15.intfNames()[0]} -C 50 -W 1 -w "{pcap_path}" &')

    # TRAFICO BENIGNO
    info("*** Iniciando tráfico benigno de fondo (ICMP, TCP, UDP)...\\n")
    # Ping normal constante h1 -> h15
    h1.cmd(f'ping {h15.IP()} -i 0.5 > /dev/null 2>&1 &')
    
    # TCP iperf h14 -> h2
    h2.cmd('iperf -s &')
    time.sleep(1)
    h14.cmd(f'iperf -c {h2.IP()} -t 300 > /dev/null 2>&1 &')
    
    # UDP iperf h13 -> h3
    h3.cmd('iperf -su &')
    time.sleep(1)
    h13.cmd(f'iperf -u -c {h3.IP()} -b 500k -t 300 > /dev/null 2>&1 &')

    # Esperar un poco para establecer el trafico legitimo (1 minuto)
    time.sleep(60)

    # ATAQUES DDoS
    victim_ip = h15.IP()
    
    info("*** \\n")
    info("*** [ATAQUE 1] Iniciando UDP Flood desde h4 a h15...\\n")
    # -d 40 => L2 ~82 bytes (mediana CICFlowMeter udp_flood); OpenFlow cuenta Ethernet.
    h4.cmd(f'hping3 --udp --flood -d 40 {victim_ip} > /dev/null 2>&1 &')
    
    time.sleep(90) # Permitir que actue el ataque y el controlador lo detenga
    
    info("*** [ATAQUE 2] Iniciando TCP SYN Flood desde h5 a h15...\\n")
    h5.cmd(f'hping3 -S --flood -p 80 {victim_ip} > /dev/null 2>&1 &')
    
    time.sleep(90)
    
    info("*** [ATAQUE 3] Iniciando ICMP Flood desde h6 a h15...\\n")
    # -d 685 => IP length ~713-727 (mediana icmp_flood CICFlowMeter).
    h6.cmd(f'hping3 -1 --flood -d 685 {victim_ip} > /dev/null 2>&1 &')
    
    time.sleep(90)
    
    info("*** [ATAQUE 4] Iniciando Slow-rate DDoS desde h7 a h15 (Generalización)\\n")
    # Menos agresivo: 100 paquetes por segundo
    h7.cmd(f'hping3 -S -p 80 -i u10000 {victim_ip} > /dev/null 2>&1 &')
    
    info("*** \\n")
    info("*** Simulación corriendo. Esperando minutos restantes para analisis (10 min en total)...\\n")
    
    # Mantener corriendo para capturar
    time.sleep(270)
    
    info("*** Finalizando simulación.\\n")
    stop_all(net)

if __name__ == '__main__':
    # Verificar root (Mininet require root)
    if os.geteuid() != 0:
        print("Este script debe ejecutarse con sudo.")
        exit(1)
    start_simulation()
