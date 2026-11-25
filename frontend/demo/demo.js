// The live demo's stand-in for the PortBridge server.
//
// The demo is the real dashboard (same pages, scripts and styles) served as plain
// static files. This script is loaded first and replaces `fetch` for the server's
// own addresses (/api/..., /auth/...), answering from a small in-browser copy of a
// WireGuard server: sample peers, rules and traffic. Nothing is sent anywhere.
// Edits last for the browser tab (sessionStorage) and are lost when it closes.
(() => {
    'use strict';

    const STORE_KEY = 'portbridge.demo.state';
    const REPOSITORY_URL = 'https://github.com/nooblk-98/portbridge';
    const NETWORK = '10.8.0';
    const ENDPOINT = '203.0.113.10:51820';
    const SERVER_PUBLIC_KEY = 'q7Lw3mV1xT5nH8cZk2PfYb0RdE6aJ9uGoS4iNvXtM1U=';

    const now = () => Math.floor(Date.now() / 1000);

    // ---- sample data ------------------------------------------------------

    const SAMPLE_PEERS = [
        { name: 'home-server', host: 2, key: 'hS3rVr0a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8=', up: 'online', rx: 1_840_000_000, tx: 5_210_000_000,
            routes: ['192.168.1.0/24'] },
        { name: 'laptop', host: 3, key: 'lAp7oP0a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8=', up: 'online', rx: 920_000_000, tx: 310_000_000, routes: [] },
        { name: 'phone', host: 4, key: 'pH0nE0a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8s=', up: 'online', rx: 410_000_000, tx: 96_000_000, routes: [] },
        { name: 'office-router', host: 5, key: 'oFf1cE0a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8=', up: 'online', rx: 2_300_000_000, tx: 1_100_000_000,
            routes: ['10.20.0.0/24'] },
        { name: 'tablet', host: 6, key: 'tAb1eT0a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8s=', up: 'offline', rx: 64_000_000, tx: 12_000_000, routes: [] },
    ];

    function seedState() {
        const clients = SAMPLE_PEERS.map(peer => ({
            name: peer.name,
            address: `${NETWORK}.${peer.host}/24`,
            public_key: peer.key,
            status: peer.up,
            rx_bytes: peer.rx,
            tx_bytes: peer.tx,
            offlineSince: peer.up === 'offline' ? now() - 3 * 86400 : null,
            options: {
                advertised_routes: peer.routes,
                dns: '1.1.1.1',
                keepalive: 25,
                local_access: false,
                mtu: null,
                // The office network may only be used by the laptop.
                route_access: peer.name === 'office-router' ? { '10.20.0.0/24': [SAMPLE_PEERS[1].key] } : {},
                split_tunnel: true,
            },
            profile_refresh_required: null,
            import_required: null,
            new_routes: [],
        }));
        const forwardings = [
            { port: '8443', target_port: '443', protocol: 'tcp', client_ip: `${NETWORK}.2`, source_ip: null },
            { port: '2222', target_port: '22', protocol: 'tcp', client_ip: `${NETWORK}.2`, source_ip: '198.51.100.7' },
            { port: '25565', target_port: null, protocol: 'tcp', client_ip: `${NETWORK}.3`, source_ip: null },
            { port: '51413', target_port: null, protocol: 'udp', client_ip: `${NETWORK}.3`, source_ip: null },
            { port: '18000-18010', target_port: null, protocol: 'tcp', client_ip: `${NETWORK}.2`, source_ip: null },
        ];
        return { clients, forwardings };
    }

    let state;
    try {
        state = JSON.parse(sessionStorage.getItem(STORE_KEY));
    } catch {
        state = null;
    }
    if (!state || !Array.isArray(state.clients)) state = seedState();

    function save() {
        try {
            sessionStorage.setItem(STORE_KEY, JSON.stringify(state));
        } catch {
            // Storage is blocked: edits still last until the page reloads.
        }
    }

    // ---- answers ----------------------------------------------------------

    class ApiError extends Error {
        constructor(status, description) {
            super(description);
            this.status = status;
            this.description = description;
        }
    }

    const keyOf = name => state.clients.find(client => client.name === name);

    /** Online peers re-handshake about every two minutes; offline ones last spoke days ago. */
    function handshakeOf(client) {
        if (client.status === 'offline') return client.offlineSince;
        const seed = [...client.name].reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
        return now() - ((now() + seed * 7) % 110) - 3;
    }

    const isOnline = client => client.status !== 'offline';

    function routeRows() {
        const rows = [];
        for (const owner of state.clients) {
            for (const cidr of owner.options.advertised_routes) {
                const allowed = owner.options.route_access[cidr];
                rows.push({
                    cidr,
                    owner_name: owner.name,
                    owner_public_key: owner.public_key,
                    owner_online: isOnline(owner),
                    owner_last_handshake: handshakeOf(owner),
                    allowed_peer_public_keys: Array.isArray(allowed) ? allowed : null,
                });
            }
        }
        return rows;
    }

    function clientsResponse() {
        const items = state.clients.map(client => ({
            address: client.address,
            config: `/clients/${client.name}.conf`,
            forwardings: state.forwardings
                .filter(rule => rule.client_ip === client.address.split('/')[0])
                .map(rule => ({ ...rule, peer_public_key: client.public_key })),
            last_handshake: handshakeOf(client),
            name: client.name,
            online: isOnline(client),
            options: client.options,
            public_key: client.public_key,
            rx_bytes: client.rx_bytes,
            tx_bytes: client.tx_bytes,
        }));
        return {
            forwardings_available: true,
            items,
            routes: routeRows(),
            server_public_key: SERVER_PUBLIC_KEY,
            split_tunnel_profiles: state.clients.map(client => ({
                import_required: client.import_required,
                name: client.name,
                new_routes: client.new_routes,
                profile_refresh_required: client.profile_refresh_required,
            })),
        };
    }

    /** A smooth, repeatable traffic curve: a daily rhythm plus some ripple. */
    function historyResponse(range) {
        const spec = { '1h': [60, 60], '24h': [96, 900], '7d': [168, 3600] }[range] || [60, 60];
        const [count, step] = spec;
        const end = Math.floor(now() / step) * step;
        const points = [];
        for (let index = count - 1; index >= 0; index -= 1) {
            const t = end - index * step;
            const hour = ((t % 86400) / 3600);
            const daily = 0.55 + 0.45 * Math.sin(((hour - 9) / 24) * 2 * Math.PI);
            const ripple = 0.75 + 0.25 * Math.sin(t / (step * 3.1)) + 0.15 * Math.sin(t / (step * 0.9));
            const scale = step / 60;
            points.push({
                t,
                download: Math.round(900_000 * scale * daily * ripple),
                upload: Math.round(310_000 * scale * daily * (1.1 - 0.2 * ripple)),
            });
        }
        // Each peer's share of the period, from its all-time traffic, scaled to what the chart shows.
        const total = points.reduce((sum, point) => sum + point.download + point.upload, 0);
        const weight = state.clients.reduce((sum, client) => sum + client.rx_bytes + client.tx_bytes, 0) || 1;
        const topTalkers = state.clients
            .filter(client => client.rx_bytes + client.tx_bytes > 0)
            .map(client => {
                const share = (client.rx_bytes + client.tx_bytes) / weight;
                const downloadShare = client.tx_bytes / (client.rx_bytes + client.tx_bytes);
                return {
                    name: client.name,
                    public_key: client.public_key,
                    total: Math.round(total * share),
                    download: Math.round(total * share * downloadShare),
                    upload: Math.round(total * share * (1 - downloadShare)),
                };
            })
            .sort((a, b) => b.total - a.total)
            .slice(0, 5);
        const sum = key => points.reduce((all, point) => all + point[key], 0);
        return {
            from: points[0].t,
            points,
            range,
            step,
            to: end,
            top_talkers: topTalkers,
            totals: { download: sum('download'), upload: sum('upload') },
        };
    }

    function statsResponse() {
        const online = state.clients.filter(isOnline).length;
        const rx = state.clients.reduce((sum, client) => sum + client.rx_bytes, 0);
        const tx = state.clients.reduce((sum, client) => sum + client.tx_bytes, 0);
        const wobble = (amount, period) => amount * (1 + 0.5 * Math.sin(Date.now() / period));
        return {
            generated_at: now(),
            health: {
                checks: [
                    { detail: 'wg0 is up', id: 'interface', label: 'WireGuard interface', status: 'ok' },
                    { detail: 'Listening on UDP 51820', id: 'port', label: 'WireGuard port', status: 'ok' },
                    { detail: `${online} of ${state.clients.length} online`, id: 'peers', label: 'Peers', status: 'ok' },
                    { detail: 'Forwarding chains are applied', id: 'firewall', label: 'Firewall rules', status: 'ok' },
                    { detail: 'Enabled', id: 'forwarding', label: 'IP forwarding', status: 'ok' },
                    { detail: 'Blocked (ALLOW_INTERNET_EGRESS=0)', id: 'egress', label: 'Internet access', status: 'ok' },
                ],
                status: 'ok',
            },
            peers: {
                items: state.clients.map(client => ({
                    last_handshake: handshakeOf(client),
                    name: client.name,
                    online: isOnline(client),
                    public_key: client.public_key,
                })),
                online,
                total: state.clients.length,
            },
            system: {
                cores: 4,
                cpu_percent: wobble(6, 4000),
                disk_mount: '/',
                disk_percent: 41.7,
                disk_total: 120_000_000_000,
                disk_used: 50_040_000_000,
                load: [0.31, 0.27, 0.22],
                memory_percent: 38 + wobble(2, 9000),
                memory_total: 8_000_000_000,
                memory_used: 3_100_000_000,
                uptime_seconds: 18 * 86400 + 5 * 3600 + Math.floor(performance.now() / 1000),
            },
            traffic: {
                download_total: tx,
                last_24h: { download: Math.round(tx * 0.04), upload: Math.round(rx * 0.04) },
                since: now() - 18 * 86400,
                upload_total: rx,
            },
            version: window.PORTBRIDGE_DEMO_VERSION || 'demo',
        };
    }

    // ---- changes ----------------------------------------------------------

    const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
    const NAME_ERROR = 'Use 1 to 32 letters, numbers, dashes or underscores, starting with a letter or number.';

    function randomKey() {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let key = '';
        for (let index = 0; index < 43; index += 1) key += alphabet[Math.floor(Math.random() * alphabet.length)];
        return `${key}=`;
    }

    function createClient(body) {
        const name = String(body.name || '').trim();
        if (!NAME_PATTERN.test(name)) throw new ApiError(422, NAME_ERROR);
        if (keyOf(name)) throw new ApiError(409, `A client named "${name}" already exists.`);
        const used = new Set(state.clients.map(client => client.address.split('/')[0]));
        let address = String(body.address || '').trim();
        if (address) {
            address = address.split('/')[0];
            if (!address.startsWith(`${NETWORK}.`) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
                throw new ApiError(422, `The address must be inside ${NETWORK}.0/24.`);
            }
            if (used.has(address)) throw new ApiError(409, `${address} is already in use.`);
        } else {
            let host = 2;
            while (used.has(`${NETWORK}.${host}`) && host < 254) host += 1;
            address = `${NETWORK}.${host}`;
        }
        const client = {
            name,
            address: `${address}/24`,
            public_key: randomKey(),
            status: 'offline',
            rx_bytes: 0,
            tx_bytes: 0,
            offlineSince: null,
            options: { advertised_routes: [], dns: '1.1.1.1', keepalive: 25, local_access: false, mtu: null, route_access: {}, split_tunnel: true },
            profile_refresh_required: null,
            import_required: null,
            new_routes: [],
        };
        state.clients.push(client);
        return { name };
    }

    function renameClient(name, body) {
        const client = keyOf(name);
        if (!client) throw new ApiError(404, 'That client does not exist.');
        const next = String(body.name || '').trim();
        if (!NAME_PATTERN.test(next)) throw new ApiError(422, NAME_ERROR);
        if (next !== name && keyOf(next)) throw new ApiError(409, `A client named "${next}" already exists.`);
        client.name = next;
        return { name: next };
    }

    function deleteClient(name) {
        const client = keyOf(name);
        if (!client) throw new ApiError(404, 'That client does not exist.');
        const address = client.address.split('/')[0];
        state.clients = state.clients.filter(other => other !== client);
        state.forwardings = state.forwardings.filter(rule => rule.client_ip !== address);
        return {};
    }

    function saveOptions(name, body) {
        const client = keyOf(name);
        if (!client) throw new ApiError(404, 'That client does not exist.');
        const previous = client.options;
        const routes = Array.isArray(body.advertised_routes) ? body.advertised_routes : previous.advertised_routes;
        client.options = {
            advertised_routes: routes,
            dns: body.dns || '',
            keepalive: Number(body.keepalive) || 0,
            local_access: Boolean(body.local_access),
            mtu: body.mtu === null || body.mtu === undefined || body.mtu === '' ? null : Number(body.mtu),
            route_access: body.route_access && typeof body.route_access === 'object' ? body.route_access : previous.route_access,
            split_tunnel: body.split_tunnel !== false,
        };
        // The changed profile has to be downloaded again, then imported on the device.
        client.profile_refresh_required = true;
        return client.options;
    }

    function addForwarding(body) {
        const port = String(body.port || '').trim();
        if (!/^\d{1,5}(-\d{1,5})?$/.test(port)) throw new ApiError(422, 'Enter a port such as 8080, or a range such as 18000-18010.');
        const ip = String(body.client_ip || '').trim();
        const owner = state.clients.find(client => client.address.split('/')[0] === ip);
        if (!owner) throw new ApiError(422, 'Choose one of your clients as the destination.');
        const protocols = body.protocol === 'both' || !body.protocol ? ['tcp', 'udp'] : [body.protocol];
        for (const protocol of protocols) {
            if (state.forwardings.some(rule => rule.port === port && rule.protocol === protocol)) {
                throw new ApiError(409, `${protocol.toUpperCase()} port ${port} is already forwarded.`);
            }
        }
        for (const protocol of protocols) {
            state.forwardings.push({
                port,
                target_port: body.target_port ? String(body.target_port) : null,
                protocol,
                client_ip: ip,
                source_ip: body.source_ip ? String(body.source_ip).trim() : null,
            });
        }
        return {};
    }

    function removeForwarding(port, protocol) {
        const before = state.forwardings.length;
        state.forwardings = state.forwardings.filter(rule => !(rule.port === port && rule.protocol === protocol));
        if (state.forwardings.length === before) throw new ApiError(404, 'That rule does not exist.');
        return {};
    }

    /** Downloading a profile records the export; the device then has to import it. */
    function recordDownload(name) {
        const client = keyOf(name);
        if (!client) return;
        client.profile_refresh_required = false;
        if (client.options.split_tunnel) {
            const others = state.clients.filter(other => other !== client).flatMap(other => other.options.advertised_routes);
            client.new_routes = others.filter(route => !(client.options.advertised_routes || []).includes(route));
            client.import_required = client.new_routes.length > 0 ? true : null;
        }
    }

    // ---- routing ----------------------------------------------------------

    function handle(method, path, query, body) {
        let match;
        if (method === 'POST' && path === '/auth/login') return { status: 'ok' };
        if (method === 'POST' && path === '/auth/logout') return { status: 'ok' };
        if (method === 'GET' && path === '/api/state') {
            return { address: `${NETWORK}.1/24`, clients: state.clients.length, endpoint: ENDPOINT, forwardings: state.forwardings.length, interface: 'wg0', network: `${NETWORK}.0/24`, version: 'demo' };
        }
        if (method === 'GET' && path === '/api/stats') return statsResponse();
        if (method === 'GET' && path === '/api/stats/history') return historyResponse(query.get('range') || '1h');
        if (method === 'GET' && path === '/api/wg/status') return { output: [] };
        if (method === 'GET' && path === '/api/clients') return clientsResponse();
        if (method === 'POST' && path === '/api/clients') return mutate(() => createClient(body));
        if (method === 'GET' && path === '/api/forwardings') return { items: clientsResponse().items.flatMap(client => client.forwardings) };
        if (method === 'POST' && path === '/api/forwardings') return mutate(() => addForwarding(body));
        if ((match = /^\/api\/forwardings\/([^/]+)\/([^/]+)$/.exec(path)) && method === 'DELETE') {
            return mutate(() => removeForwarding(decodeURIComponent(match[1]), decodeURIComponent(match[2])));
        }
        if ((match = /^\/api\/clients\/([^/]+)\/options$/.exec(path)) && method === 'PATCH') {
            return mutate(() => saveOptions(decodeURIComponent(match[1]), body));
        }
        if ((match = /^\/api\/clients\/([^/]+)\/profile-imported$/.exec(path)) && method === 'POST') {
            return mutate(() => {
                const client = keyOf(decodeURIComponent(match[1]));
                if (client) { client.import_required = null; client.new_routes = []; }
                return {};
            });
        }
        if ((match = /^\/api\/clients\/([^/]+)$/.exec(path))) {
            if (method === 'PATCH') return mutate(() => renameClient(decodeURIComponent(match[1]), body));
            if (method === 'DELETE') return mutate(() => deleteClient(decodeURIComponent(match[1])));
        }
        throw new ApiError(404, 'Not found');
    }

    function mutate(change) {
        const result = change();
        save();
        return result;
    }

    // ---- fetch ------------------------------------------------------------

    const realFetch = window.fetch.bind(window);

    window.fetch = (input, init = {}) => {
        const url = new URL(typeof input === 'string' ? input : input.url, window.location.href);
        if (url.origin !== window.location.origin || !/^\/(api|auth)\//.test(url.pathname)) {
            return realFetch(input, init);
        }
        const method = String(init.method || (typeof input !== 'string' && input.method) || 'GET').toUpperCase();
        let body = {};
        try {
            body = init.body ? JSON.parse(init.body) : {};
        } catch {
            body = {};
        }
        const respond = (status, payload) => new Response(JSON.stringify(payload), {
            status,
            headers: { 'Content-Type': 'application/json' },
        });
        return new Promise(resolve => {
            // A little latency, so loading states are visible like they are for real.
            setTimeout(() => {
                try {
                    resolve(respond(200, handle(method, url.pathname, url.searchParams, body)));
                } catch (error) {
                    if (error instanceof ApiError) resolve(respond(error.status, { description: error.description }));
                    else resolve(respond(500, { description: 'The demo hit an unexpected error.' }));
                }
            }, 120);
        });
    };

    // ---- the page around it -----------------------------------------------

    /** A sample profile for the "Download Config" link; the keys are made up. */
    function sampleProfile(client) {
        const lines = [
            '[Interface]',
            `# Sample profile from the PortBridge demo. These keys are not real.`,
            'PrivateKey = DEMO-PRIVATE-KEY-NOT-REAL-DO-NOT-USE-0000000=',
            `Address = ${client.address}`,
            client.options.dns ? `DNS = ${client.options.dns}` : null,
            '',
            '[Peer]',
            `PublicKey = ${SERVER_PUBLIC_KEY}`,
            `Endpoint = ${ENDPOINT}`,
            `AllowedIPs = ${[`${NETWORK}.0/24`, ...state.clients.flatMap(other => other.options.advertised_routes)].join(', ')}`,
            client.options.keepalive ? `PersistentKeepalive = ${client.options.keepalive}` : null,
        ];
        return `${lines.filter(line => line !== null).join('\n')}\n`;
    }

    document.addEventListener('click', event => {
        const link = event.target.closest && event.target.closest('a[href^="/clients/"][href$=".conf"]');
        if (!link) return;
        event.preventDefault();
        const name = decodeURIComponent(link.getAttribute('href').slice('/clients/'.length, -'.conf'.length));
        const client = keyOf(name);
        if (!client) return;
        const url = URL.createObjectURL(new Blob([sampleProfile(client)], { type: 'text/plain' }));
        const download = document.createElement('a');
        download.href = url;
        download.download = `${name}.conf`;
        document.body.append(download);
        download.click();
        download.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        mutate(() => recordDownload(name));
    }, true);

    function onReady() {
        // Every QR code is the same sample picture, since no server draws them here.
        const qr = new MutationObserver(() => {
            document.querySelectorAll('img[alt="QR Code"]').forEach(image => {
                const sample = '/static/img/demo-qr.png';
                if (image.getAttribute('src') && !image.getAttribute('src').startsWith(sample)) image.setAttribute('src', sample);
            });
        });
        qr.observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['src'] });

        // A small note that this is a demo, out of the way of the page's own layout.
        const note = document.createElement('div');
        note.setAttribute('data-testid', 'demo-note');
        note.style.cssText = [
            'position:fixed', 'left:12px', 'right:12px', 'bottom:12px', 'margin:0 auto', 'width:fit-content', 'z-index:2147483000',
            'box-sizing:border-box', 'display:flex', 'align-items:center', 'justify-content:center', 'gap:10px',
            'max-width:calc(100vw - 24px)', 'padding:8px 14px', 'border-radius:16px', 'background:rgba(15,23,42,0.92)', 'color:#f8fafc', 'font:500 13px/1.3 Inter,system-ui,sans-serif',
            'box-shadow:0 6px 24px rgba(0,0,0,0.3)', 'backdrop-filter:blur(6px)',
        ].join(';');
        const text = document.createElement('span');
        text.textContent = 'Live demo with sample data. Changes stay in this tab.';
        text.style.cssText = 'min-width:0';
        const link = document.createElement('a');
        link.href = REPOSITORY_URL;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'Get PortBridge';
        link.style.cssText = 'color:#7dd3fc;font-weight:600;text-decoration:underline;white-space:nowrap;flex:none';
        const close = document.createElement('button');
        close.type = 'button';
        close.setAttribute('aria-label', 'Hide demo note');
        close.textContent = '×';
        close.style.cssText = 'background:none;border:0;color:#cbd5e1;font-size:18px;line-height:1;cursor:pointer;padding:0 2px;flex:none';
        close.addEventListener('click', () => note.remove());
        note.append(text, link, close);
        document.body.append(note);

        // The sign-in page accepts anything; say so.
        const password = document.querySelector('input[type="password"]');
        if (password) {
            password.placeholder = 'Type anything to look around';
            const hint = document.createElement('p');
            hint.textContent = 'This is a demo. Any password works.';
            hint.style.cssText = 'margin:8px 0 0;font-size:13px;opacity:0.75;text-align:center';
            password.closest('form')?.append(hint);
        }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
    else onReady();
})();
