import ipaddress

DEFAULTS = {
    "advertised_routes": [],
    "split_tunnel": False,
    "dns": "1.1.1.1",
    "mtu": None,
    "keepalive": 25,
}


def peer_options(client):
    return {key: client.get(key, value) for key, value in DEFAULTS.items()}


def validate_options(options, client, clients, network):
    if not isinstance(options, dict) or options.keys() - DEFAULTS.keys():
        raise ValueError("Invalid peer options.")
    result = peer_options(client) | options
    routes = result["advertised_routes"]
    if not isinstance(routes, list) or len(routes) > 32:
        raise ValueError("Enter up to 32 advertised IPv4 routes.")
    occupied = [network]
    for peer in clients:
        if peer["name"] != client["name"]:
            occupied.extend(map(ipaddress.IPv4Network, peer_options(peer)["advertised_routes"]))
    normalized = []
    for value in routes:
        if not isinstance(value, str):
            raise ValueError("Each advertised route must be an IPv4 address or CIDR.")
        route = ipaddress.IPv4Network(value.strip())
        if route.prefixlen == 0 or any(route.overlaps(other) for other in occupied):
            raise ValueError(f"Advertised route overlaps another route: {route}")
        for reserved in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"):
            if route.overlaps(ipaddress.IPv4Network(reserved)):
                raise ValueError(f"Reserved addresses cannot be advertised: {route}")
        occupied.append(route)
        normalized.append(str(route))
    result["advertised_routes"] = sorted(normalized)
    if type(result["split_tunnel"]) is not bool:
        raise ValueError("Split tunnel must be enabled or disabled.")
    dns = result["dns"]
    if not isinstance(dns, str):
        raise ValueError("DNS must be a comma-separated list of IP addresses.")
    result["dns"] = ", ".join(str(ipaddress.ip_address(item.strip())) for item in dns.split(",") if item.strip())
    for key, lower, upper in (("mtu", 1280, 9000), ("keepalive", 0, 65535)):
        value = result[key]
        if key == "mtu" and value is None:
            continue
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"{key.upper()} must be between {lower} and {upper}.")
    return result
