from collections import defaultdict
import datetime
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3
import numpy as np
import pandas as pd

try:
    import joblib
except ImportError:
    joblib = None

# CICFlowMeter AdDDoSDN: pkt_len de UDP flood ~82 = Eth(14)+IP(20)+UDP(8)+payload(40).
# OpenFlow byte_count en OVS es L2 sin FCS. NO restar Ethernet (eso cegó el modelo el 2026-08-14).
ETH_HDR = 14
TCP_SYN, TCP_RST, TCP_PSH = 0x02, 0x04, 0x08
# Recortar flags al rango del dataset (CICFlowMeter cuenta flags por microflujo, no millones).
FLAG_CLIP = 5
ICMP_FLAG = -1.0  # CICFlowMeter marca -1 en ICMP

FEATURE_NAMES = [
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


def _mean_len(byte_count, n_pkts):
    if n_pkts <= 0:
        return 0.0
    return float(byte_count) / float(n_pkts)


class SimpleDDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDDoSDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."

        self.log_file = os.path.join(base_dir, "detecciones_ryu.csv")
        with open(self.log_file, "w") as f:
            f.write(
                "Time,Switch,SrcIP,DstIP,Duration,FwdPkts,BwdPkts,Prediction,P_attack,"
                "PredLatency_ms,Protocol,down_up_ratio,flow_pkts_s,rst_flag_cnt,pkt_len_min,"
                "bwd_pkts_s,fwd_pkts_s,bwd_pkt_len_min,fwd_pkt_len_max,syn_flag_cnt,fwd_psh_flags\n"
            )

        self.mac_to_port = {}
        self.pkt_flags = defaultdict(lambda: {"syn": 0, "rst": 0, "psh": 0})
        self.ml_ready = False
        try:
            self.model = joblib.load(os.path.join(base_dir, "ryu_rf_model.pkl"))
            self.scaler = joblib.load(os.path.join(base_dir, "ryu_scaler.pkl"))
            self.logger.info("Modelo RF y Scaler cargados (11 features).")
            self.ml_ready = True
        except Exception as e:
            self.logger.error("Error al cargar modelo ML: %s", e)

        self.monitor_thread  # keep ref

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Registrado datapath: %s", datapath.id)
                self.datapaths[datapath.id] = datapath
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                self.add_flow(
                    datapath,
                    0,
                    parser.OFPMatch(),
                    [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
                    hard_timeout=0,
                    idle_timeout=0,
                )
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            proto = pkt_ipv4.proto
            src, dst = pkt_ipv4.src, pkt_ipv4.dst
            if proto == 6:
                t = pkt.get_protocol(tcp.tcp)
                if t is not None:
                    bits = t.bits
                    fl = self.pkt_flags[(src, dst, proto)]
                    if bits & TCP_SYN:
                        fl["syn"] += 1
                    if bits & TCP_RST:
                        fl["rst"] += 1
                    if bits & TCP_PSH:
                        fl["psh"] += 1
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(
                    datapath,
                    10,
                    parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src,
                        ipv4_dst=dst,
                        ip_proto=proto,
                    ),
                    actions,
                )

        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(
                datapath,
                1,
                parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src),
                actions,
            )

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
        )

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(5)

    def _flags_for_proto(self, proto, syn_n, rst_n, psh_n):
        if proto == 1:
            return ICMP_FLAG, ICMP_FLAG, ICMP_FLAG
        if proto == 17:
            return 0.0, 0.0, 0.0
        return (
            float(min(syn_n, FLAG_CLIP)),
            float(min(rst_n, FLAG_CLIP)),
            float(min(psh_n, FLAG_CLIP)),
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if not self.ml_ready:
            return
        dpid = ev.msg.datapath.id
        agg = defaultdict(
            lambda: {
                "fwd_pkts": 0,
                "fwd_bytes": 0,
                "duration": 0.0,
                "syn": 0,
                "rst": 0,
                "psh": 0,
                "fwd_lens": [],
            }
        )

        for stat in ev.msg.body:
            if stat.priority not in (10, 15):
                continue
            src_ip = stat.match.get("ipv4_src")
            dst_ip = stat.match.get("ipv4_dst")
            proto = stat.match.get("ip_proto", 0)
            if not src_ip or not dst_ip:
                continue
            key = (src_ip, dst_ip, proto)
            a = agg[key]
            a["fwd_pkts"] += stat.packet_count
            a["fwd_bytes"] += stat.byte_count
            dur = stat.duration_sec + (stat.duration_nsec / 1e9)
            if dur > a["duration"]:
                a["duration"] = dur
            mean_l = _mean_len(stat.byte_count, stat.packet_count)
            if stat.packet_count > 0 and mean_l > 0:
                a["fwd_lens"].append(mean_l)

        seen = set()
        for (src_ip, dst_ip, proto), fwd in agg.items():
            pair = (src_ip, dst_ip, proto)
            if pair in seen:
                continue
            seen.add(pair)
            seen.add((dst_ip, src_ip, proto))

            bwd = agg.get((dst_ip, src_ip, proto))
            dur = max(fwd["duration"], bwd["duration"] if bwd else 0.0, 1e-6)
            if dur < 0.2:
                continue

            fwd_p = fwd["fwd_pkts"]
            bwd_p = bwd["fwd_pkts"] if bwd else 0
            if fwd_p + bwd_p < 2:
                continue

            fwd_p_s = fwd_p / dur
            bwd_p_s = bwd_p / dur
            flow_pkts_s = (fwd_p + bwd_p) / dur
            down_up = (bwd_p / fwd_p) if fwd_p > 0 else 0.0

            fwd_lens = list(fwd["fwd_lens"])
            bwd_lens = list(bwd["fwd_lens"]) if bwd else []
            fwd_pkt_len_max = max(fwd_lens) if fwd_lens else _mean_len(fwd["fwd_bytes"], fwd_p)
            bwd_pkt_len_min = min(bwd_lens) if bwd_lens else 0.0
            all_lens = fwd_lens + bwd_lens
            pkt_len_min = min(all_lens) if all_lens else 0.0

            fl = self.pkt_flags.get((src_ip, dst_ip, proto), {"syn": 0, "rst": 0, "psh": 0})
            fl_b = self.pkt_flags.get((dst_ip, src_ip, proto), {"syn": 0, "rst": 0, "psh": 0})
            syn_f, rst_f, psh_f = self._flags_for_proto(
                proto, fl["syn"], fl["rst"] + fl_b["rst"], fl["psh"]
            )

            vec = np.array(
                [
                    [
                        down_up,
                        flow_pkts_s,
                        rst_f,
                        pkt_len_min,
                        bwd_p_s,
                        fwd_p_s,
                        bwd_pkt_len_min,
                        fwd_pkt_len_max,
                        syn_f,
                        psh_f,
                        float(proto),
                    ]
                ]
            )
            try:
                feat_scaled = self.scaler.transform(pd.DataFrame(vec, columns=FEATURE_NAMES))
                t0 = time.time()
                prediction = int(self.model.predict(feat_scaled)[0])
                p_attack = float(self.model.predict_proba(feat_scaled)[0][1])
                pred_latency_ms = (time.time() - t0) * 1000
            except Exception as e:
                self.logger.error("Error prediciendo: %s", e)
                continue

            is_attack = prediction == 1
            if not is_attack and proto == 6 and p_attack >= 0.3 and fwd_p > 50:
                raw_syn = fl.get("syn", 0)
                if raw_syn > 10 and down_up < 0.1:
                    is_attack = True
                    self.logger.info(
                        "SYN-heuristic triggered: %s->%s syn=%d down_up=%.3f p=%.3f",
                        src_ip, dst_ip, raw_syn, down_up, p_attack,
                    )

            if is_attack:
                self.logger.warning(
                    "ALERTA DDoS: %s -> %s proto=%s p=%.2f pkts=%s len_min=%.0f syn=%s dur=%.2f %.2fms",
                    src_ip,
                    dst_ip,
                    proto,
                    p_attack,
                    fwd_p,
                    pkt_len_min,
                    syn_f,
                    dur,
                    pred_latency_ms,
                )
                datapath = ev.msg.datapath
                parser = datapath.ofproto_parser
                datapath.send_msg(
                    parser.OFPFlowMod(
                        datapath=datapath,
                        priority=100,
                        match=parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip),
                        instructions=[],
                        hard_timeout=30,
                    )
                )

            try:
                with open(self.log_file, "a") as f:
                    f.write(
                        f"{datetime.datetime.now()},{dpid},{src_ip},{dst_ip},{dur:.4f},"
                        f"{fwd_p},{bwd_p},{prediction},{p_attack:.4f},{pred_latency_ms:.4f},{proto},"
                        f"{down_up:.4f},{flow_pkts_s:.4f},{rst_f},{pkt_len_min:.2f},"
                        f"{bwd_p_s:.4f},{fwd_p_s:.4f},{bwd_pkt_len_min:.2f},{fwd_pkt_len_max:.2f},"
                        f"{syn_f},{psh_f}\n"
                    )
            except OSError as e:
                self.logger.error("No se pudo escribir detecciones_ryu.csv: %s", e)
