// The peer settings dialog: advertised routes, per-route access, split tunnel and network options.
(() => {
    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).peerSettings = () => ({
        peerFormKey: '',
        routeFormError: '',

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
    });
})();
