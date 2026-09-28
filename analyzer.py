
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import IP, UDP, ESP

def analyze_ipsec_capture(packets):
    ike_count = 0
    esp_count = 0
    nat_t_count = 0
    endpoints = set()
    esp_sessions = defaultdict(list)
    ike_udp500 = 0
    ike_nat_t = 0
    esp_nat_t = 0

    for packet in packets:
        if IP in packet:
            endpoints.add((packet[IP].src, packet[IP].dst))

        if UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
            if sport == 4500 or dport == 4500:
                nat_t_count += 1

        if packet.haslayer("ISAKMP"):
            ike_count += 1
            if UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                if sport == 500 or dport == 500:
                    ike_udp500 += 1
                elif sport == 4500 or dport == 4500:
                    ike_nat_t += 1
            continue

        if ESP in packet:
            esp_count += 1
            if UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                if sport == 4500 or dport == 4500:
                    esp_nat_t += 1
            src, dst = packet[IP].src, packet[IP].dst
            esp_sessions[(src, dst, hex(packet[ESP].spi))].append(packet[ESP].seq)

    result = {
        "ipsec_detected": ike_count > 0 or esp_count > 0,
        "transport": {"nat_t_detected": nat_t_count > 0, "udp_4500_packets": nat_t_count},
        "ike": {"detected": ike_count > 0, "packet_count": ike_count,
                "udp_500_packets": ike_udp500, "nat_t_packets": ike_nat_t},
        "esp": {"detected": esp_count > 0, "packet_count": esp_count,
                "nat_t_packets": esp_nat_t},
        "endpoints": [{"source": s, "destination": d} for s, d in sorted(endpoints)],
        "security_associations": []
    }
    for (src, dst, spi), seqs in sorted(esp_sessions.items()):
        result["security_associations"].append({
            "source": src, "destination": dst, "spi": spi,
            "packet_count": len(seqs), "sequence_numbers": seqs
        })
    return result

def extract_flow_features(packets):
    esp_packets = [p for p in packets if IP in p and ESP in p]
    if len(esp_packets) < 2:
        return {"esp_packets": len(esp_packets), "message": "Not enough ESP packets for flow statistics."}

    times = np.array([float(p.time) for p in esp_packets])
    sizes = np.array([len(p) for p in esp_packets], dtype=float)
    iat = np.diff(np.sort(times))
    duration = float(times.max() - times.min())
    return {
        "esp_packets": len(esp_packets),
        "average_packet_size": round(float(sizes.mean()), 2),
        "min_packet_size": int(sizes.min()),
        "max_packet_size": int(sizes.max()),
        "average_inter_arrival": round(float(iat.mean()), 6) if len(iat) else 0,
        "flow_duration": round(duration, 6),
        "flow_packets_per_second": round(len(esp_packets) / duration, 4) if duration else 0,
        "flow_bytes_per_second": round(float(sizes.sum()) / duration, 2) if duration else 0
    }

def assess_ipsec_security_evidence(result):
    findings = []
    findings.append({
        "check":"IPsec traffic presence",
        "status":"PASS" if result["ipsec_detected"] else "WARNING",
        "evidence":"IKE and/or ESP traffic was observed." if result["ipsec_detected"] else "No IKE or ESP traffic was observed."
    })
    findings.append({
        "check":"IKE traffic observed",
        "status":"PASS" if result["ike"]["detected"] else "UNKNOWN",
        "evidence":f'{result["ike"]["packet_count"]} IKE packets observed.' if result["ike"]["detected"] else "No IKE packets were present in the analyzed capture."
    })
    findings.append({
        "check":"ESP protected traffic observed",
        "status":"PASS" if result["esp"]["detected"] else "WARNING",
        "evidence":f'{result["esp"]["packet_count"]} ESP packets observed.' if result["esp"]["detected"] else "No ESP packets were observed."
    })

    sequence_ok = all(
        len(sa["sequence_numbers"]) <= 1 or sa["sequence_numbers"] == sorted(sa["sequence_numbers"])
        for sa in result["security_associations"]
    )
    findings.append({
        "check":"ESP sequence progression",
        "status":"PASS" if sequence_ok else "WARNING",
        "evidence":"Observed ESP sequence numbers increase monotonically within each observed security association."
                    if sequence_ok else "Non-monotonic ESP sequence progression was observed."
    })

    directions = {(sa["source"], sa["destination"]) for sa in result["security_associations"]}
    findings.append({
        "check":"Bidirectional ESP traffic",
        "status":"PASS" if len(directions) >= 2 else "UNKNOWN",
        "evidence":"ESP traffic observed in both directions." if len(directions) >= 2 else "Only one ESP direction observed."
    })

    for check, evidence in [
        ("Anti-replay configuration", "A passive capture can show sequence behavior, but it does not by itself establish the configured anti-replay window."),
        ("Cryptographic configuration", "The analyzed evidence does not independently establish the complete negotiated cryptographic policy."),
        ("PFS / DH configuration", "PFS/DH configuration cannot be reliably assessed from the currently analyzed evidence."),
        ("SA lifetime configuration", "Configured SA lifetime is not established from this passive capture.")
    ]:
        findings.append({"check":check, "status":"UNKNOWN", "evidence":evidence})
    return findings
