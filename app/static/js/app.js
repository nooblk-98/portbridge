
// Each dashboard page has its own URL so it can be bookmarked and shared.
const PAGES = [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', path: '/' },
    { id: 'clients', label: 'Clients', icon: 'group', path: '/clients' },
    { id: 'routes', label: 'Routes', icon: 'route', path: '/routes' },
    { id: 'forwarding', label: 'Forwarding', icon: 'alt_route', path: '/forwarding' }
];

function pageForPath(pathname) {
    const clean = pathname.replace(/\/+$/, '') || '/';
    return (PAGES.find(page => page.path === clean) || PAGES[0]).id;
}

// Chart.js must not be wrapped by Alpine's reactive proxy, so it lives here.
let trafficChart = null;

function app() {
    return {
        currentTab: pageForPath(window.location.pathname),
        mobileMenuOpen: false,
        isDarkMode: window.PortBridgeTheme.isDark(),
        state: {},
        stats: null,
        history: null,
        historyRange: '1h',
        historyRequestId: 0,
        historyRanges: [
            { id: '1h', label: '1 h' },
            { id: '24h', label: '24 h' },
            { id: '7d', label: '7 d' }
        ],
        statsTick: 0,
        clients: [],
        forwardings: [],
        forwardingError: '',
        routes: [],
        routeRows: [],
        restrictedRouteCount: 0,
        blockedRouteCount: 0,
        routesAvailable: false,
        splitTunnelProfiles: [],
        profileRows: [],
        profilesNeedingExport: 0,
        importNotices: [],
        importBusy: false,
        splitTunnelProfilesAvailable: false,
        searchClient: '',
        activeClient: null,
        peerFormKey: '',
        routeFormError: '',
        lastFocusedElement: null,

        modals: {
            client: false,
            fwd: false,
            qr: false,
            options: false,
            rename: false,
            confirmDelete: false,
            confirmDeleteFwd: false,
        },

        forms: {
            client: { name: '', address: '' },
            fwd: { port: '', target_port: '', protocol: 'both', client_ip: '', source_ip: '' },
            options: {},
            rename: { oldName: '', newName: '' },
        },

        pendingDelete: { type: null, name: null, port: null, proto: null },

        loading: {
            logout: false,
            createClient: false,
            createFwd: false,
            options: false,
            rename: false,
            delete: false,
        },

        toast: {
            show: false,
            message: '',
            type: 'success'
        },

        navItems: PAGES,

        initApp() {
            // Keep the address bar, tab title and back/forward buttons in step
            // with the visible page.
            const showPage = tab => {
                const page = PAGES.find(item => item.id === tab);
                if (!page) return;
                if (window.location.pathname.replace(/\/+$/, '') !== page.path.replace(/\/+$/, '')) {
                    history.pushState({ tab }, '', page.path);
                }
                document.title = `${page.label} \u00b7 PortBridge`;
                if (tab === 'dashboard') {
                    this.loadStats();
                    this.loadHistory();
                    this.$nextTick(() => { if (trafficChart) trafficChart.resize(); });
                }
            };
            this.$watch('currentTab', showPage);
            window.addEventListener('popstate', () => {
                this.currentTab = pageForPath(window.location.pathname);
            });
            showPage(this.currentTab);
            this.setupTooltips();

            this.loadData();
            setInterval(() => this.loadData(), 30000);
            // Live numbers every 10 seconds while the dashboard is visible; the
            // chart refreshes about once a minute, like the server samples.
            setInterval(() => {
                if (document.hidden || this.currentTab !== 'dashboard') return;
                this.loadStats();
                this.statsTick += 1;
                if (this.statsTick % 6 === 0) this.loadHistory();
            }, 10000);

            // theme.js owns the stored choice and the <html> class; follow it.
            window.PortBridgeTheme.subscribe(dark => {
                this.isDarkMode = dark;
                if (trafficChart) this.renderTrafficChart(true);
            });
        },

        /** Allow or block Docker containers and other traffic forwarded through the PortBridge server from reaching a peer's services. */
        async toggleLocalAccess(client, event) {
            const input = event.target;
            const enabled = input.checked;
            input.disabled = true;
            try {
                await fetch(`/api/clients/${encodeURIComponent(client.name)}/options`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ local_access: enabled }),
                }).then(this.checkAuth);
                this.showToast(enabled
                    ? `Server access on for ${client.name}. Containers on the PortBridge server can now reach its services.`
                    : `Server access off for ${client.name}. Containers on the PortBridge server can no longer reach its services.`);
                await this.loadData();
            } catch (error) {
                input.checked = !enabled;
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                this.showToast(details?.description || 'Could not change server access', 'error');
            } finally {
                input.disabled = false;
            }
        },

        /** Tooltips open on hover and focus; Escape dismisses them without moving focus. */
        setupTooltips() {
            document.addEventListener('keydown', event => {
                if (event.key !== 'Escape') return;
                document.querySelectorAll('.pb-tip:hover, .pb-tip:focus-within')
                    .forEach(tip => { tip.dataset.dismissed = ''; });
            });
            const rearm = event => {
                const tip = event.target.closest && event.target.closest('.pb-tip');
                if (tip && !tip.contains(event.relatedTarget)) delete tip.dataset.dismissed;
            };
            document.addEventListener('mouseout', rearm);
            document.addEventListener('focusout', rearm);
        },

        /** Switch a peer between split tunnel and full tunnel from its card. */
        async toggleSplitTunnel(client, event) {
            const input = event.target;
            const enabled = input.checked;
            input.disabled = true;
            try {
                await fetch(`/api/clients/${encodeURIComponent(client.name)}/options`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ split_tunnel: enabled }),
                }).then(this.checkAuth);
                this.showToast(enabled
                    ? `Split tunnel on for ${client.name}. Re-import its profile on the device.`
                    : `Full tunnel on for ${client.name}: all its traffic uses the PortBridge hosted server. Re-import its profile.`);
                await this.loadData();
            } catch (error) {
                input.checked = !enabled;
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                this.showToast(details?.description || 'Could not change split tunnel', 'error');
            } finally {
                input.disabled = false;
            }
        },

        /** Confirm that peers imported their updated profiles on the device (all when no name is given). */
        async acknowledgeImports(name) {
            const names = name ? [name] : this.importNotices.map(notice => notice.name);
            if (names.length === 0 || this.importBusy) return;
            this.importBusy = true;
            try {
                for (const peer of names) {
                    await fetch(`/api/clients/${encodeURIComponent(peer)}/profile-imported`, {
                        method: 'POST',
                    }).then(this.checkAuth);
                }
                this.showToast(names.length === 1
                    ? `Marked ${names[0]} as imported.`
                    : `Marked ${names.length} peers as imported.`);
                await this.loadData();
            } catch (error) {
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                this.showToast(details?.description || 'Could not record the import', 'error');
            } finally {
                this.importBusy = false;
            }
        },

        /** Cartoon avatar for a peer, seeded by its public key so it survives renames. */
        avatarFor(client) {
            const avatars = window.PortBridgeAvatar;
            return avatars ? avatars.dataUri(client.public_key || client.name) : '';
        },

        // ---- dashboard statistics -------------------------------------------------

        formatRate(bytesPerSecond) {
            if (!bytesPerSecond || bytesPerSecond < 1) return '0 B/s';
            return this.formatBytes(bytesPerSecond) + '/s';
        },

        formatDuration(seconds) {
            if (!seconds) return '0m';
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            if (days) return `${days}d ${hours}h`;
            if (hours) return `${hours}h ${minutes}m`;
            return `${minutes}m`;
        },

        /** `stroke-dasharray` for a ring that is `percent` full. */
        ringDash(percent) {
            const circumference = 2 * Math.PI * 50;
            const clamped = Math.max(0, Math.min(100, percent || 0));
            return `${((clamped / 100) * circumference).toFixed(1)} ${circumference.toFixed(1)}`;
        },

        toneFor(percent, warnAt = 70, critAt = 90) {
            if (percent >= critAt) return 'pb-tone-crit';
            if (percent >= warnAt) return 'pb-tone-warn';
            return 'pb-tone-ok';
        },

        get peerRows() {
            const items = this.stats?.peers?.items || [];
            return [...items].sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
        },
        /** Rows shown in the card; the rest are summarised so the list never needs a scrollbar. */
        get peerRowsShown() { return this.peerRows.slice(0, 5); },
        get peersHidden() { return Math.max(0, this.peerRows.length - 5); },
        get peersTotal() { return this.stats?.peers?.total || 0; },
        get peersOnline() { return this.stats?.peers?.online || 0; },
        get peersOnlinePct() {
            return this.peersTotal ? (this.peersOnline / this.peersTotal) * 100 : 0;
        },
        get peersTone() {
            if (this.peersTotal === 0) return 'pb-tone-warn';
            if (this.peersOnline === 0) return 'pb-tone-crit';
            return this.peersOnline === this.peersTotal ? 'pb-tone-ok' : 'pb-tone-warn';
        },

        get trafficTotal() {
            return (this.stats?.traffic?.download_total || 0) + (this.stats?.traffic?.upload_total || 0);
        },
        get downloadShare() {
            return this.trafficTotal ? Math.round(((this.stats.traffic.download_total || 0) / this.trafficTotal) * 100) : 0;
        },
        get uploadShare() {
            return this.trafficTotal ? 100 - this.downloadShare : 0;
        },
        get trafficSince() {
            const since = this.stats?.traffic?.since;
            if (!since) return 'Collecting data. Totals start with the first reading.';
            const date = new Date(since * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
            return `Counting since ${date}. Totals survive restarts.`;
        },

        get healthStatus() { return this.stats?.health?.status || 'ok'; },
        get healthChecks() { return this.stats?.health?.checks || []; },
        get healthLabel() {
            return { ok: 'Healthy', warn: 'Attention', fail: 'Problem' }[this.healthStatus] || '';
        },

        get historyRangeLabel() {
            return { '1h': 'Last hour', '24h': 'Last 24 hours', '7d': 'Last 7 days' }[this.historyRange];
        },
        get chartIsEmpty() {
            const totals = this.history?.totals;
            return !totals || (totals.upload === 0 && totals.download === 0);
        },
        get chartSummary() {
            if (!this.history || this.chartIsEmpty) return '';
            const step = this.history.step;
            const peak = Math.max(...this.history.points.map(point => (point.upload + point.download) / step));
            return `Peak ${this.formatRate(peak)}`;
        },
        get talkers() {
            const items = this.history?.top_talkers || [];
            const max = Math.max(1, ...items.map(item => item.total));
            return items.map(item => ({ ...item, share: Math.max(3, Math.round((item.total / max) * 100)) }));
        },

        get gauges() {
            const system = this.stats?.system;
            if (!system) return [];
            const cpu = Math.round(system.cpu_percent || 0);
            const memory = Math.round(system.memory_percent || 0);
            const disk = Math.round(system.disk_percent || 0);
            return [
                { key: 'cpu', label: 'CPU', icon: 'memory', pct: cpu, tone: this.toneFor(cpu), sub: `${system.cores} core${system.cores === 1 ? '' : 's'}` },
                { key: 'memory', label: 'Memory', icon: 'developer_board', pct: memory, tone: this.toneFor(memory), sub: `${this.formatBytes(system.memory_used)} of ${this.formatBytes(system.memory_total)}` },
                { key: 'disk', label: 'Disk', icon: 'storage', pct: disk, tone: this.toneFor(disk), sub: `${this.formatBytes(system.disk_used)} of ${this.formatBytes(system.disk_total)}${system.disk_mount ? ' on ' + system.disk_mount : ''}` }
            ];
        },
        get loadRows() {
            const system = this.stats?.system;
            if (!system) return [];
            const cores = system.cores || 1;
            return ['1 min', '5 min', '15 min'].map((label, index) => {
                const value = system.load?.[index] || 0;
                const ratio = value / cores;
                return {
                    label,
                    value: value.toFixed(2),
                    pct: Math.min(100, Math.round(ratio * 100)),
                    tone: this.toneFor(ratio * 100, 70, 100)
                };
            });
        },
        get loadNote() {
            const cores = this.stats?.system?.cores || 1;
            return `A load near ${cores} means all ${cores === 1 ? 'the' : cores} CPU core${cores === 1 ? '' : 's'} ${cores === 1 ? 'is' : 'are'} busy.`;
        },
        get serverFooter() {
            const system = this.stats?.system;
            if (!system) return '';
            return `Up ${this.formatDuration(system.uptime_seconds)} · PortBridge v${this.stats.version}`;
        },

        async loadStats() {
            try {
                const response = await fetch('/api/stats').then(this.checkAuth);
                this.stats = await response.json();
            } catch (error) {
                // Keep showing the last numbers; the next poll retries.
            }
        },

        async loadHistory() {
            const requestId = ++this.historyRequestId;
            try {
                const response = await fetch(`/api/stats/history?range=${encodeURIComponent(this.historyRange)}`).then(this.checkAuth);
                const history = await response.json();
                if (requestId !== this.historyRequestId) return;
                this.history = history;
                this.renderTrafficChart();
            } catch (error) {
                // Keep the previous chart.
            }
        },

        setHistoryRange(range) {
            if (this.historyRange === range) return;
            this.historyRange = range;
            this.loadHistory();
        },

        chartLabel(timestamp) {
            const date = new Date(timestamp * 1000);
            const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            if (this.historyRange === '7d') {
                return `${date.toLocaleDateString([], { weekday: 'short' })} ${time}`;
            }
            return time;
        },

        /** Draw or update the traffic chart. `recreate` rebuilds it, for theme changes. */
        renderTrafficChart(recreate = false) {
            const canvas = this.$refs.trafficCanvas;
            if (!canvas || !window.Chart || !this.history) return;
            const dark = this.isDarkMode;
            const step = this.history.step;
            const points = this.history.points;
            const grid = dark ? 'rgba(148, 163, 184, 0.14)' : 'rgba(100, 116, 139, 0.16)';
            const ticks = dark ? '#94a3b8' : '#64748b';
            const fill = (color) => (context) => {
                const { ctx, chartArea } = context.chart;
                if (!chartArea) return 'transparent';
                const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                gradient.addColorStop(0, color + '55');
                gradient.addColorStop(1, color + '00');
                return gradient;
            };
            const datasets = [
                { label: 'Download', data: points.map(point => point.download / step), borderColor: '#0ea5e9', backgroundColor: fill('#0ea5e9'), fill: true },
                { label: 'Upload', data: points.map(point => point.upload / step), borderColor: '#6366f1', backgroundColor: fill('#6366f1'), fill: true }
            ];
            const labels = points.map(point => this.chartLabel(point.t));

            if (trafficChart && recreate) {
                trafficChart.destroy();
                trafficChart = null;
            }
            if (trafficChart) {
                trafficChart.data.labels = labels;
                trafficChart.data.datasets.forEach((dataset, index) => { dataset.data = datasets[index].data; });
                trafficChart.update();
                return;
            }
            trafficChart = new window.Chart(canvas, {
                type: 'line',
                data: { labels, datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 350 },
                    interaction: { mode: 'index', intersect: false },
                    elements: { line: { tension: 0.35, borderWidth: 2 }, point: { radius: 0, hoverRadius: 4 } },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#0f172a',
                            titleColor: '#e2e8f0',
                            bodyColor: '#e2e8f0',
                            padding: 10,
                            cornerRadius: 10,
                            boxPadding: 4,
                            callbacks: { label: (item) => ` ${item.dataset.label}: ${this.formatRate(item.parsed.y)}` }
                        }
                    },
                    scales: {
                        x: { grid: { display: false }, border: { display: false }, ticks: { color: ticks, maxTicksLimit: 6, maxRotation: 0, autoSkip: true } },
                        y: { beginAtZero: true, grid: { color: grid }, border: { display: false }, ticks: { color: ticks, maxTicksLimit: 5, callback: (value) => this.formatRate(value) } }
                    }
                }
            });
        },

        toggleTheme() {
            window.PortBridgeTheme.toggle();
        },

        async logout() {
            if (this.loading.logout) return;
            this.loading.logout = true;
            try {
                const response = await fetch('/auth/logout', { method: 'POST' });
                if (!response.ok && response.status !== 401) throw response;
                window.location.href = '/login';
            } catch (error) {
                this.showToast('Could not sign out. Please try again.', 'error');
            } finally {
                this.loading.logout = false;
            }
        },

        checkAuth(res) {
            if (res.status === 401) {
                window.location.href = '/login';
                throw { status: 401 };
            }
            if (!res.ok) throw res;
            return res;
        },

        async loadData() {
            try {
                const forwarding = this.loadForwardings();
                const [stateRes, clientsRes] = await Promise.all([
                    fetch('/api/state').then(this.checkAuth),
                    fetch('/api/clients').then(this.checkAuth)
                ]);

                this.state = await stateRes.json();
                const clientsData = await clientsRes.json();
                this.clients = Array.isArray(clientsData.items) ? clientsData.items : [];
                this.routes = Array.isArray(clientsData.routes) ? clientsData.routes : [];
                this.routesAvailable = Array.isArray(clientsData.routes);
                this.splitTunnelProfiles = Array.isArray(clientsData.split_tunnel_profiles)
                    ? clientsData.split_tunnel_profiles
                    : [];
                this.splitTunnelProfilesAvailable = Array.isArray(clientsData.split_tunnel_profiles);
                this.buildRouteView();
                await forwarding;
            } catch (err) {
                if (err.status === 401) return;
                console.error('Failed to load data', err);
            }
        },

        async loadForwardings() {
            try {
                const response = await fetch('/api/forwardings').then(this.checkAuth);
                this.forwardings = (await response.json()).items;
                this.forwardingError = '';
            } catch (error) {
                if (error.status === 401) return;
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                this.forwardingError = details?.description || 'Could not load forwarding rules.';
            }
        },

        get filteredClients() {
            if (!this.searchClient) return this.clients;
            const term = this.searchClient.toLowerCase();
            return this.clients.filter(c =>
                c.name.toLowerCase().includes(term) ||
                c.address.includes(term)
            );
        },

        getClientName(ip) {
            if (!ip) return 'Unknown';
            const client = this.clients.find(c => c.address.split('/')[0] === ip);
            return client ? client.name : 'Unknown';
        },

        formatTime(timestamp) {
            if (!timestamp) return 'Never';
            const diff = Math.floor(Date.now() / 1000) - timestamp;
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        },

        formatBytes(bytes) {
            if (!bytes || bytes < 1) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        showToast(message, type = 'success') {
            this.toast.message = message;
            this.toast.type = type;
            this.toast.show = true;
            setTimeout(() => { this.toast.show = false; }, 3000);
        },

        openClientModal() {
            this.forms.client = { name: '', address: '' };
            this.modals.client = true;
        },

        openFwdModal() {
            this.forms.fwd = { port: '', target_port: '', protocol: 'both', client_ip: '', source_ip: '' };
            this.modals.fwd = true;
        },

        showQR(client) {
            this.activeClient = client;
            this.modals.qr = true;
        },

        openPeerOptions(client, focusCidr = '') {
            const savedRoutes = Array.isArray(client.options.advertised_routes) ? client.options.advertised_routes : [];
            const savedAccess = client.options.route_access;
            const source = savedAccess && typeof savedAccess === 'object'
                ? savedAccess
                : (window.PortBridgeRoutes.routeAccessMap(this.routes) || {});
            const draftAccess = {};
            savedRoutes.forEach(cidr => {
                if (Object.prototype.hasOwnProperty.call(source, cidr) && Array.isArray(source[cidr])) {
                    draftAccess[cidr] = source[cidr].slice();
                }
            });

            this.lastFocusedElement = document.activeElement;
            this.peerFormKey = client.public_key || '';
            this.routeFormError = '';
            this.forms.options = {
                ...client.options,
                name: client.name,
                routes: savedRoutes.join(', '),
                saved_routes: savedRoutes,
                route_access: draftAccess,
            };
            this.modals.options = true;

            this.$nextTick(() => {
                if (focusCidr) {
                    const section = document.getElementById(this.routeAnchorId(focusCidr));
                    if (section) {
                        section.scrollIntoView({ block: 'center' });
                        const radio = section.querySelector('input[type="radio"]');
                        if (radio) {
                            radio.focus();
                            return;
                        }
                    }
                }
                if (this.$refs.peerDialog) this.$refs.peerDialog.focus();
            });
        },

        closePeerOptions() {
            if (this.loading.options) return;
            this.modals.options = false;
            this.routeFormError = '';
            const target = this.lastFocusedElement;
            this.lastFocusedElement = null;
            if (target && typeof target.focus === 'function') target.focus();
        },

        trapFocus(event, container) {
            if (!container) return;
            const focusable = container.querySelectorAll(
                'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
            );
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && (document.activeElement === first || document.activeElement === container)) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        },

        /*
         * Route rows are flattened into display strings on every load. Alpine
         * reuses an x-for element when its key is unchanged, so deriving labels
         * lazily from a row object can leave a stale value on screen after a
         * save. A fresh view model plus keys that include the access state make
         * the update deterministic, including for the 30-second refresh.
         */
        buildRouteView() {
            const rows = this.routes.toSorted((a, b) =>
                String(a.cidr).localeCompare(String(b.cidr), undefined, { numeric: true })
            );
            this.routeRows = rows.map(row => {
                const access = window.PortBridgeRoutes.effectiveAccess(row, this.clients);
                let label = 'All peers';
                let tone = 'muted';
                let detail = 'Every connected peer may use this route.';
                if (access.mode === 'none') {
                    label = 'Blocked for everyone';
                    tone = 'danger';
                    detail = 'No peer may use this route.';
                } else if (access.mode === 'orphaned') {
                    label = 'Blocked';
                    tone = 'danger';
                    detail = 'The allowed peers no longer exist, so the route is blocked.';
                } else if (access.mode === 'selected') {
                    label = `${access.allowedCount} of ${access.total} peers`;
                    tone = 'ok';
                    const names = access.names.slice(0, 3).join(', ');
                    const extra = access.names.length > 3 ? ` +${access.names.length - 3} more` : '';
                    const stale = access.stale > 0
                        ? ` ${access.stale} saved ${access.stale === 1 ? 'key' : 'keys'} no longer match a peer.`
                        : '';
                    detail = names + extra + stale;
                }
                return {
                    ...row,
                    access_label: label,
                    access_tone: tone,
                    access_detail: detail,
                    handshake_label: row.owner_last_handshake ? this.formatTime(row.owner_last_handshake) : 'Never',
                };
            });

            this.restrictedRouteCount = rows.filter(row =>
                window.PortBridgeRoutes.effectiveAccess(row, this.clients).mode === 'selected'
            ).length;
            this.blockedRouteCount = rows.filter(row => {
                const mode = window.PortBridgeRoutes.effectiveAccess(row, this.clients).mode;
                return mode === 'none' || mode === 'orphaned';
            }).length;

            this.profileRows = this.splitTunnelProfiles.map(profile => {
                const status = window.PortBridgeRoutes.profileStatus(
                    profile ? profile.profile_refresh_required : null
                );
                return {
                    name: profile.name,
                    status_text: status.text,
                    status_tone: status.tone,
                    status_icon: status.icon,
                };
            });
            this.profilesNeedingExport = this.profileRows.filter(row => row.status_tone === 'warn').length;
            this.importNotices = this.splitTunnelProfiles
                .filter(profile => profile && profile.import_required === true)
                .map(profile => ({
                    name: profile.name,
                    routes: Array.isArray(profile.new_routes) ? profile.new_routes : [],
                }));
        },

        editRouteAccess(route) {
            const owner = this.clients.find(client => client.public_key === route.owner_public_key);
            if (!owner) {
                this.showToast('The peer that owns this route no longer exists.', 'error');
                return;
            }
            this.openPeerOptions(owner, route.cidr);
        },

        get optionRoutes() {
            return window.PortBridgeRoutes.parseRouteList(this.forms.options.routes);
        },

        get optionRouteErrors() {
            return this.optionRoutes.filter(route => !route.ok);
        },

        get routeCandidatePeers() {
            return this.clients.filter(client => client.public_key !== this.peerFormKey);
        },

        routeAnchorId(value) {
            return 'route-access-' + String(value || 'new').replace(/[^A-Za-z0-9]+/g, '-');
        },

        routeMode(cidr) {
            const access = this.forms.options.route_access || {};
            return Array.isArray(access[cidr]) ? 'selected' : 'all';
        },

        setRouteMode(cidr, mode) {
            if (!this.forms.options.route_access) this.forms.options.route_access = {};
            if (mode === 'all') {
                delete this.forms.options.route_access[cidr];
            } else if (!Array.isArray(this.forms.options.route_access[cidr])) {
                this.forms.options.route_access[cidr] = [];
            }
        },

        routeAllows(cidr, publicKey) {
            const list = (this.forms.options.route_access || {})[cidr];
            return Array.isArray(list) && list.includes(publicKey);
        },

        routeSelectedCount(cidr) {
            const list = (this.forms.options.route_access || {})[cidr];
            return Array.isArray(list) ? list.length : 0;
        },

        toggleRoutePeer(cidr, publicKey, checked) {
            if (!this.forms.options.route_access) this.forms.options.route_access = {};
            const list = Array.isArray(this.forms.options.route_access[cidr])
                ? this.forms.options.route_access[cidr]
                : [];
            const next = list.filter(key => key !== publicKey);
            if (checked) next.push(publicKey);
            this.forms.options.route_access[cidr] = next;
        },

        async savePeerOptions() {
            const entries = this.optionRoutes;
            if (entries.length > 32) {
                this.routeFormError = 'Enter up to 32 advertised IPv4 routes.';
                return;
            }
            if (entries.some(entry => !entry.ok)) {
                this.routeFormError = 'Fix the routes marked below before saving.';
                const field = document.getElementById('peer-routes');
                if (field) field.focus();
                return;
            }
            this.routeFormError = '';

            const routes = entries.map(entry => entry.cidr);
            const baseMap = this.routesAvailable
                ? window.PortBridgeRoutes.routeAccessMap(this.routes)
                : null;
            const options = { ...this.forms.options };
            delete options.name;
            delete options.routes;
            delete options.saved_routes;
            options.advertised_routes = routes;
            options.mtu = options.mtu === '' ? null : options.mtu;
            if (baseMap !== null) {
                options.route_access = window.PortBridgeRoutes.buildAccessPayload(
                    baseMap,
                    this.forms.options.saved_routes || [],
                    routes,
                    this.forms.options.route_access || {}
                );
            } else {
                delete options.route_access;
            }

            this.loading.options = true;
            try {
                await fetch(`/api/clients/${encodeURIComponent(this.forms.options.name)}/options`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(options),
                }).then(this.checkAuth);
                this.modals.options = false;
                this.lastFocusedElement = null;
                this.showToast('Peer settings saved. Download the updated profile.');
                await this.loadData();
            } catch (error) {
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                this.showToast(details?.description || 'Could not save peer settings', 'error');
            } finally {
                this.loading.options = false;
            }
        },

        openRenameModal(client) {
            this.forms.rename = { oldName: client.name, newName: client.name };
            this.modals.rename = true;
        },

        confirmDeleteClient(name) {
            this.pendingDelete = { type: 'client', name, port: null, proto: null };
            this.modals.confirmDelete = true;
        },

        confirmDeleteForwarding(port, proto) {
            this.pendingDelete = { type: 'forwarding', name: null, port, proto };
            this.modals.confirmDeleteFwd = true;
        },

        async createClient() {
            this.loading.createClient = true;
            try {
                const res = await fetch('/api/clients', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.forms.client)
                }).then(this.checkAuth);

                const data = await res.json();
                this.showToast(`Client ${data.name} created!`);
                this.modals.client = false;
                this.loadData();
            } catch (err) {
                try {
                    const data = await err.json();
                    this.showToast(data.description || 'Error creating client', 'error');
                } catch (e) {
                    this.showToast('Error creating client', 'error');
                }
            } finally {
                this.loading.createClient = false;
            }
        },

        async renameClient() {
            this.loading.rename = true;
            try {
                await fetch(`/api/clients/${encodeURIComponent(this.forms.rename.oldName)}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: this.forms.rename.newName })
                }).then(this.checkAuth);

                this.showToast('Client renamed');
                this.modals.rename = false;
                this.loadData();
            } catch (err) {
                try {
                    const data = await err.json();
                    this.showToast(data.description || 'Error renaming client', 'error');
                } catch (e) {
                    this.showToast('Error renaming client', 'error');
                }
            } finally {
                this.loading.rename = false;
            }
        },

        async executeDelete() {
            this.loading.delete = true;
            try {
                if (this.pendingDelete.type === 'client') {
                    await fetch(`/api/clients/${encodeURIComponent(this.pendingDelete.name)}`, { method: 'DELETE' }).then(this.checkAuth);
                    this.showToast('Client deleted');
                } else {
                    const encodedPort = encodeURIComponent(this.pendingDelete.port);
                    await fetch(`/api/forwardings/${encodedPort}/${this.pendingDelete.proto}`, { method: 'DELETE' }).then(this.checkAuth);
                    this.showToast('Rule removed');
                }
                this.modals.confirmDelete = false;
                this.modals.confirmDeleteFwd = false;
                this.loadData();
            } catch (err) {
                this.showToast('Error deleting item', 'error');
            } finally {
                this.loading.delete = false;
            }
        },

        async createForwarding() {
            this.loading.createFwd = true;
            try {
                await fetch('/api/forwardings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.forms.fwd)
                }).then(this.checkAuth);

                this.showToast('Forwarding rule added!');
                this.modals.fwd = false;
                this.loadData();
            } catch (err) {
                try {
                    const data = await err.json();
                    this.showToast(data.description || 'Error creating rule', 'error');
                } catch (e) {
                    this.showToast('Error creating rule', 'error');
                }
            } finally {
                this.loading.createFwd = false;
            }
        },
    }
}
