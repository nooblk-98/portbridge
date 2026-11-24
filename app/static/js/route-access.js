/*
 * Route and access helpers for PortBridge.
 *
 * Pure functions only: no DOM, no Alpine, no network. They normalise typed
 * routes the same way the server stores them, turn the /api/clients route rows
 * into an editable access map, and describe effective access for display.
 */
(function (root, factory) {
    var api = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.PortBridgeRoutes = api;
    }
})(typeof window !== 'undefined' ? window : null, function () {
    'use strict';

    // The private ranges a peer may advertise; mirrors `is_private` in src/model.rs.
    var PRIVATE_RANGES = [
        [0x0a000000, 8], // 10.0.0.0/8
        [0xac100000, 12], // 172.16.0.0/12
        [0xc0a80000, 16], // 192.168.0.0/16
        [0x64400000, 10] // 100.64.0.0/10
    ];

    var HOST_ERROR = 'Enter a valid IPv4 address, such as 192.168.50.10.';
    var PREFIX_ERROR = 'Prefix must be a number from 0 to 32.';
    var PRIVATE_ERROR = 'Use a private or shared address: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10.';

    function parseIPv4(value) {
        if (typeof value !== 'string') return null;
        var parts = value.trim().split('.');
        if (parts.length !== 4) return null;
        var result = 0;
        for (var i = 0; i < parts.length; i += 1) {
            var part = parts[i];
            if (!/^\d{1,3}$/.test(part)) return null;
            var octet = Number(part);
            if (octet > 255) return null;
            result = result * 256 + octet;
        }
        return result;
    }

    function formatIPv4(number) {
        return [
            Math.floor(number / 16777216) % 256,
            Math.floor(number / 65536) % 256,
            Math.floor(number / 256) % 256,
            number % 256
        ].join('.');
    }

    function withinPrivateRange(network, prefix) {
        var size = Math.pow(2, 32 - prefix);
        for (var i = 0; i < PRIVATE_RANGES.length; i += 1) {
            var base = PRIVATE_RANGES[i][0];
            var span = Math.pow(2, 32 - PRIVATE_RANGES[i][1]);
            if (network >= base && network + size <= base + span) return true;
        }
        return false;
    }

    /*
     * Normalise one typed entry. Host entries gain /32, host bits are cleared
     * for larger prefixes, and the result is the canonical CIDR the server
     * saves, so an access entry can be keyed on it.
     */
    function normalizeRoute(value) {
        var raw = typeof value === 'string' ? value.trim() : '';
        var failure = function (message) {
            return { ok: false, cidr: '', error: message, abbreviated: false, hostBits: false };
        };
        if (!raw) return failure('Enter an IPv4 address or CIDR.');

        var pieces = raw.split('/');
        if (pieces.length > 2) return failure('Use one address, optionally followed by /prefix.');

        var address = parseIPv4(pieces[0]);
        if (address === null) return failure(HOST_ERROR);

        var prefix = 32;
        var abbreviated = pieces.length === 1;
        if (pieces.length === 2) {
            var prefixText = pieces[1].trim();
            if (!/^\d{1,2}$/.test(prefixText)) return failure(PREFIX_ERROR);
            prefix = Number(prefixText);
            if (prefix > 32) return failure(PREFIX_ERROR);
        }

        var size = Math.pow(2, 32 - prefix);
        var network = Math.floor(address / size) * size;
        var cidr = formatIPv4(network) + '/' + prefix;

        if (!withinPrivateRange(network, prefix)) return failure(PRIVATE_ERROR);

        return {
            ok: true,
            cidr: cidr,
            error: '',
            abbreviated: abbreviated,
            hostBits: address !== network
        };
    }

    /*
     * Parse the free-text field into entries. Duplicate canonical routes are
     * errors because the access map has one entry per canonical CIDR.
     */
    function parseRouteList(text) {
        var tokens = String(text === null || text === undefined ? '' : text)
            .split(/[\s,]+/)
            .filter(Boolean);
        var entries = tokens.map(function (token) {
            var parsed = normalizeRoute(token);
            parsed.raw = token;
            return parsed;
        });

        var counts = {};
        entries.forEach(function (entry) {
            if (!entry.ok) return;
            counts[entry.cidr] = (counts[entry.cidr] || 0) + 1;
        });
        entries.forEach(function (entry) {
            if (entry.ok && counts[entry.cidr] > 1) {
                entry.ok = false;
                entry.error = 'This route is listed more than once.';
            }
        });
        return entries;
    }

    /* null means every connected peer; an array (even empty) is a selection. */
    function accessList(value) {
        if (!Array.isArray(value)) return null;
        return value.filter(function (key) {
            return typeof key === 'string' && key;
        });
    }

    /* Complete access map from route rows: only restricted entries are stored. */
    function routeAccessMap(rows) {
        if (!Array.isArray(rows)) return null;
        var map = {};
        rows.forEach(function (row) {
            if (!row || typeof row.cidr !== 'string') return;
            var list = accessList(row.allowed_peer_public_keys);
            if (list !== null) map[row.cidr] = list.slice();
        });
        return map;
    }

    /*
     * Rebuild the complete map for a PATCH: start from what the server already
     * reported, drop the routes this peer used to advertise, then write back
     * the peer's current draft selections. Routes left as "all peers" have no
     * entry, which is the stored meaning of the default policy.
     */
    function buildAccessPayload(baseMap, savedRoutes, routes, draftAccess) {
        var map = {};
        Object.keys(baseMap || {}).forEach(function (cidr) {
            var list = accessList(baseMap[cidr]);
            if (list !== null) map[cidr] = list.slice();
        });
        (savedRoutes || []).forEach(function (cidr) {
            delete map[cidr];
        });
        (routes || []).forEach(function (cidr) {
            if (!draftAccess || !Object.prototype.hasOwnProperty.call(draftAccess, cidr)) return;
            map[cidr] = accessList(draftAccess[cidr]) || [];
        });
        return map;
    }

    /*
     * Effective access for one route row. Keys that no longer match a peer are
     * stale: the route stays blocked until an administrator updates it.
     */
    function effectiveAccess(row, peers) {
        var ownerKey = row && row.owner_public_key;
        var candidates = (Array.isArray(peers) ? peers : []).filter(function (peer) {
            return peer && typeof peer.public_key === 'string' && peer.public_key && peer.public_key !== ownerKey;
        });
        var allowed = accessList(row && row.allowed_peer_public_keys);
        var total = candidates.length;

        if (allowed === null) {
            return { mode: 'all', allowedCount: total, total: total, names: [], stale: 0 };
        }

        var names = [];
        var matched = 0;
        allowed.forEach(function (key) {
            var peer = null;
            for (var i = 0; i < candidates.length; i += 1) {
                if (candidates[i].public_key === key) {
                    peer = candidates[i];
                    break;
                }
            }
            if (peer) {
                matched += 1;
                names.push(peer.name);
            }
        });
        names.sort();
        var stale = allowed.length - matched;

        if (allowed.length === 0) {
            return { mode: 'none', allowedCount: 0, total: total, names: [], stale: 0 };
        }
        if (matched === 0) {
            return { mode: 'orphaned', allowedCount: 0, total: total, names: [], stale: stale };
        }
        return { mode: 'selected', allowedCount: matched, total: total, names: names, stale: stale };
    }

    var PROFILE_STATES = {
        unknown: { text: 'No export recorded', tone: 'muted', icon: 'help' },
        pending: { text: 'Export updated profile', tone: 'warn', icon: 'sync_problem' },
        current: { text: 'Current profile exported', tone: 'ok', icon: 'check_circle' }
    };

    /* null is unknown: no successful export has been recorded. */
    function profileStatus(value) {
        if (value === true) return PROFILE_STATES.pending;
        if (value === false) return PROFILE_STATES.current;
        return PROFILE_STATES.unknown;
    }

    return {
        parseRouteList: parseRouteList,
        routeAccessMap: routeAccessMap,
        buildAccessPayload: buildAccessPayload,
        effectiveAccess: effectiveAccess,
        profileStatus: profileStatus
    };
});
