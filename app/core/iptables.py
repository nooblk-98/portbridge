
import logging
import ipaddress
from app.core.config import (
    NAT_CHAIN, FILTER_CHAIN, FORWARD_FILE
)
from app.core.utils import run, load_json, save_json

def detect_primary_interface():
    try:
        result = run(["sh", "-c", "ip route show default | awk '{print $5; exit}'"], check=False)
        iface = result.stdout.strip()
        if iface:
            return iface
    except Exception:
        return "eth0"
    return "eth0"

def ensure_masquerade(ext_iface):
    check = run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"],
        check=False,
    )
    if check.returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"])

def ensure_chain(table, chain, parent_chain=None):
    run(["iptables", "-t", table, "-N", chain], check=False)
    if parent_chain:
        present = run(["iptables", "-t", table, "-C", parent_chain, "-j", chain], check=False)
        if present.returncode != 0:
            run(["iptables", "-t", table, "-A", parent_chain, "-j", chain])

def apply_forwardings(rules):
    ext_iface = detect_primary_interface()
    ensure_chain("nat", NAT_CHAIN, "PREROUTING")
    ensure_chain("filter", FILTER_CHAIN, "FORWARD")
    run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
    run(["iptables", "-t", "filter", "-F", FILTER_CHAIN])

    for rule in rules:
        try:
            port_input = str(rule["port"])
            is_range = "-" in port_input
            
            if is_range:
                start_port, end_port = map(int, port_input.split("-"))
                dport_arg = f"{start_port}:{end_port}"
            else:
                port = int(port_input)
                dport_arg = str(port)

            proto = rule.get("protocol", "both").lower()
            client_ip = str(ipaddress.ip_address(rule["client_ip"]))
            
            if is_range:
                to_dest = f"{client_ip}:{start_port}-{end_port}"
                dest_port_arg = dport_arg
            else:
                target_port = int(rule.get("target_port", port))
                to_dest = f"{client_ip}:{target_port}"
                dest_port_arg = str(target_port)

            source_ip = rule.get("source_ip", "").strip()

        except Exception as e:
            logging.error(f"Skipping invalid rule {rule}: {e}")
            continue

        protocols = ["tcp", "udp"] if proto == "both" else [proto]
        for name in protocols:
            # DNAT Rule
            dnat_cmd = [
                "iptables", "-t", "nat", "-A", NAT_CHAIN,
                "-i", ext_iface,
                "-p", name,
                "--dport", dport_arg,
                "-j", "DNAT",
                "--to-destination", to_dest
            ]
            if source_ip:
                dnat_cmd.extend(["-s", source_ip])
            
            run(dnat_cmd)

            # Filter Rule (FORWARD)
            filter_cmd = [
                "iptables", "-t", "filter", "-A", FILTER_CHAIN,
                "-p", name,
                "-d", client_ip,
                "--dport", dest_port_arg,
                "-j", "ACCEPT"
            ]
            if source_ip:
                filter_cmd.extend(["-s", source_ip])
                
            run(filter_cmd)

    ensure_masquerade(ext_iface)
    logging.info("Applied %s forwarding rules", len(rules))

def load_forwardings(default_client_ip=None):
    payload = load_json(FORWARD_FILE, None)
    if isinstance(payload, list):
        return payload

    if default_client_ip:
        seed = [{"port": 30000, "protocol": "both", "client_ip": str(default_client_ip), "target_port": 8080}]
        save_json(FORWARD_FILE, seed)
        return seed

    save_json(FORWARD_FILE, [])
    return []

def protocols_overlap(existing_proto, new_proto):
    existing = existing_proto.lower()
    new = new_proto.lower()
    if existing == "both" or new == "both":
        return True
    return existing == new
