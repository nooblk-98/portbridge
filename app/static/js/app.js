
function app() {
    return {
        currentTab: 'dashboard',
        mobileMenuOpen: false,
        isDarkMode: localStorage.getItem('theme') === 'dark',
        state: {},
        clients: [],
        forwardings: [],
        routes: [],
        routeRows: [],
        restrictedRouteCount: 0,
        blockedRouteCount: 0,
        routesAvailable: false,
        splitTunnelProfiles: [],
        profileRows: [],
        profilesNeedingExport: 0,
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

        navItems: [
            { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
            { id: 'clients', label: 'Clients', icon: 'group' },
            { id: 'routes', label: 'Routes', icon: 'route' },
            { id: 'forwarding', label: 'Forwarding', icon: 'alt_route' }
        ],

        initApp() {
            this.loadData();
            setInterval(() => this.loadData(), 30000);

            this.$watch('isDarkMode', val => {
                localStorage.setItem('theme', val ? 'dark' : 'light');
                if (val) document.documentElement.classList.add('dark');
                else document.documentElement.classList.remove('dark');
            });

            if (this.isDarkMode) document.documentElement.classList.add('dark');
        },

        toggleTheme() {
            this.isDarkMode = !this.isDarkMode;
        },

        async logout() {
            try {
                await fetch('/auth/logout', { method: 'POST' });
                window.location.href = '/login';
            } catch (e) {
                window.location.reload();
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
                const [stateRes, clientsRes, fwdRes] = await Promise.all([
                    fetch('/api/state').then(this.checkAuth),
                    fetch('/api/clients').then(this.checkAuth),
                    fetch('/api/forwardings').then(this.checkAuth)
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
                const fwdData = await fwdRes.json();
                this.forwardings = fwdData.items;
            } catch (err) {
                if (err.status === 401) return;
                console.error('Failed to load data', err);
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
            if (!bytes) return '0 B';
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
            const rows = [...this.routes].sort((a, b) =>
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
