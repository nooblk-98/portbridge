import copy
import ipaddress
from collections import Counter

PRIVATE_ROUTES = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")))

DEFAULTS = {
    "advertised_routes": [],
    "route_access": {},
    "split_tunnel": False,
    "dns": "1.1.1.1",
    "mtu": None,
    "keepalive": 25,
}


def peer_options(client):
    return {key: copy.deepcopy(client.get(key, value)) for key, value in DEFAULTS.items()}


def canonical_route(value):
    return str(ipaddress.IPv4Network(str(value).strip()))


def validated_peers(clients):
    """Peers whose public key and tunnel address are unique and valid.

    Route access is stored as public keys, so source addresses are derived from
    the stored peer list at render time. An ambiguous record is left out instead
    of guessing which address belongs to a key.
    """
    valid = []
    for client in clients:
        if not isinstance(client, dict):
            continue
        key = client.get("public_key")
        try:
            address = str(ipaddress.ip_address(client.get("address")))
        except (TypeError, ValueError):
            continue
        if not isinstance(key, str) or not key:
            continue
        valid.append((key, address, client))
    key_counts = Counter(key for key, _, _ in valid)
    address_counts = Counter(address for _, address, _ in valid)
    return [client for key, address, client in valid if key_counts[key] == 1 and address_counts[address] == 1]


def route_access_entry(client, route):
    """Return the stored recipient keys for one route.

    ``None`` means the route predates access control (or the route is not
    listed), which permits every connected peer. A list is the explicit
    allow-list; an empty list denies everyone. Corrupted or non-list values
    fail closed.
    """
    access = client.get("route_access", {})
    if access is None:
        return None
    if not isinstance(access, dict):
        return []
    cidr = canonical_route(route)
    if cidr not in access:
        return None
    value = access[cidr]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def allowed_recipient_keys(client, route, clients):
    """Return the public keys currently allowed to reach ``route``.

    ``None`` keeps the legacy behaviour: every connected peer. Selected keys
    that no longer belong to a connected peer are dropped, so deleting a peer
    revokes its access immediately.
    """
    entry = route_access_entry(client, route)
    if entry is None:
        return None
    own_key = client.get("public_key")
    connected = {peer.get("public_key") for peer in validated_peers(clients) if peer.get("public_key") != own_key}
    return {key for key in entry if key in connected}


def allowed_recipient_addresses(client, route, clients):
    """Source addresses permitted to reach ``route``, derived from peer keys."""
    owner_key = client.get("public_key")
    owner_address = client.get("address")
    peers = [
        peer
        for peer in validated_peers(clients)
        if peer.get("public_key") != owner_key and peer.get("address") != owner_address
    ]
    entry = route_access_entry(client, route)
    if entry is None:
        chosen = peers
    else:
        selected = set(entry)
        chosen = [peer for peer in peers if peer.get("public_key") in selected]
    addresses = {peer["address"] for peer in chosen}
    if owner_address:
        # The advertising peer can always use its own route.
        addresses.add(owner_address)
    return sorted(addresses, key=ipaddress.ip_address)


def may_receive_route(client, owner, route, clients):
    """Whether ``client`` may receive the advertised route owned by ``owner``."""
    if client.get("public_key") == owner.get("public_key"):
        return False
    keys = allowed_recipient_keys(owner, route, clients)
    return keys is None or client.get("public_key") in keys


def _stored_recipient_keys(value):
    stored = {}
    if not isinstance(value, dict):
        return stored
    for raw_route, keys in value.items():
        try:
            cidr = canonical_route(raw_route)
        except (TypeError, ValueError):
            continue
        if isinstance(keys, list):
            stored[cidr] = {key for key in keys if isinstance(key, str)}
    return stored


def _sanitize_route_access(value, routes, client, clients, strict_identity, previous_access=None):
    advertised = {canonical_route(route): ipaddress.IPv4Network(route) for route in routes}
    own_key = client.get("public_key")
    connected = {peer["public_key"] for peer in validated_peers(clients) if peer.get("public_key") != own_key}
    previously_stored = _stored_recipient_keys(previous_access)
    if value is None:
        value = {}
    if not isinstance(value, dict):
        if strict_identity:
            raise ValueError("Route access must map advertised routes to peer public keys.")
        return {route: [] for route in routes}

    result = {}
    for raw_route, raw_keys in value.items():
        try:
            route = ipaddress.IPv4Network(str(raw_route).strip())
        except (TypeError, ValueError):
            if strict_identity:
                raise ValueError(f"Invalid route access range: {raw_route!r}.") from None
            continue
        cidr = str(route)
        if cidr not in advertised:
            if any(route.overlaps(existing) for existing in advertised.values()):
                if strict_identity:
                    raise ValueError(f"Route access range overlaps an advertised route: {cidr}")
            continue
        if not isinstance(raw_keys, list) or len(raw_keys) > 256:
            if strict_identity:
                raise ValueError("Each route access entry must be a list of up to 256 peer public keys.")
            result[cidr] = []
            continue
        keys = []
        for key in raw_keys:
            if isinstance(key, str) and key == own_key:
                if strict_identity:
                    raise ValueError("A peer cannot grant itself route access.")
                continue
            if not isinstance(key, str):
                if strict_identity:
                    raise ValueError("Route access lists an unknown peer: <non-string>.")
                continue
            if key not in connected:
                # A recipient deleted since the last save stays revoked; it is not
                # accepted as a new selection. Values carried over from the stored
                # options are dropped instead of blocking an unrelated edit.
                if strict_identity and key not in previously_stored.get(cidr, set()):
                    raise ValueError(f"Route access lists an unknown peer: {key[:64]!r}.")
                continue
            if key not in keys:
                keys.append(key)
        result[cidr] = sorted(keys)
    return dict(sorted(result.items(), key=lambda item: ipaddress.IPv4Network(item[0])))


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
            try:
                occupied.extend(map(ipaddress.IPv4Network, peer_options(peer)["advertised_routes"]))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid stored routes for peer {peer['name']}.") from exc
    normalized = []
    for value in routes:
        if not isinstance(value, str):
            raise ValueError("Each advertised route must be an IPv4 address or CIDR.")
        route = ipaddress.IPv4Network(value.strip())
        if not any(route.subnet_of(private) for private in PRIVATE_ROUTES):
            raise ValueError(f"Advertise an address within a private or shared IPv4 range: {route}")
        if any(route.overlaps(other) for other in occupied):
            raise ValueError(f"Advertised route overlaps another route: {route}")
        occupied.append(route)
        normalized.append(str(route))
    result["advertised_routes"] = sorted(normalized)
    result["route_access"] = _sanitize_route_access(
        result["route_access"],
        result["advertised_routes"],
        client,
        clients,
        strict_identity="route_access" in options,
        previous_access=client.get("route_access"),
    )
    if type(result["split_tunnel"]) is not bool:
        raise ValueError("Split tunnel must be enabled or disabled.")
    dns = result["dns"]
    if not isinstance(dns, str) or "%" in dns:
        raise ValueError("DNS must be a comma-separated list of IP addresses.")
    result["dns"] = ", ".join(str(ipaddress.ip_address(item.strip())) for item in dns.split(",") if item.strip())
    for key, lower, upper in (("mtu", 1280, 9000), ("keepalive", 0, 65535)):
        value = result[key]
        if key == "mtu" and value is None:
            continue
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"{key.upper()} must be between {lower} and {upper}.")
    return result
