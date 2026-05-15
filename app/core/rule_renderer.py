import ipaddress
import logging
from dataclasses import dataclass


@dataclass
class IPTablesCommand:
    table: str
    args: list[str]


def render_rule(rule: dict, ext_iface: str) -> list[IPTablesCommand]:
    commands: list[IPTablesCommand] = []

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

        source_ip = (rule.get("source_ip") or "").strip()

    except Exception as e:
        logging.error("Skipping invalid rule %s: %s", rule, e)
        return []

    protocols = ["tcp", "udp"] if proto == "both" else [proto]
    for name in protocols:
        dnat_args = [
            "-i",
            ext_iface,
            "-p",
            name,
            "--dport",
            dport_arg,
            "-j",
            "DNAT",
            "--to-destination",
            to_dest,
        ]
        if source_ip:
            dnat_args.extend(["-s", source_ip])
        commands.append(IPTablesCommand(table="nat", args=dnat_args))

        filter_args = [
            "-p",
            name,
            "-d",
            client_ip,
            "--dport",
            dest_port_arg,
            "-j",
            "ACCEPT",
        ]
        if source_ip:
            filter_args.extend(["-s", source_ip])
        commands.append(IPTablesCommand(table="filter", args=filter_args))

    return commands


def protocols_overlap(existing_proto: str, new_proto: str) -> bool:
    existing = existing_proto.lower()
    new = new_proto.lower()
    if existing == "both" or new == "both":
        return True
    return existing == new
