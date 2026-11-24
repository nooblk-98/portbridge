// The Routes page: who may use each advertised route, and which profiles need a fresh export or import.
(() => {
    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).routes = () => ({
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

        /** Take the route and profile data from a clients response and rebuild the Routes view. */
        updateRoutes(data) {
            this.routes = Array.isArray(data.routes) ? data.routes : [];
            this.routesAvailable = Array.isArray(data.routes);
            this.splitTunnelProfiles = Array.isArray(data.split_tunnel_profiles)
                ? data.split_tunnel_profiles
                : [];
            this.splitTunnelProfilesAvailable = Array.isArray(data.split_tunnel_profiles);
            this.buildRouteView();
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

        /** Classes for a status pill; `tone` is ok, warn, danger or muted. */
        pillClass(tone) { return window.PortBridgeTones.PILL[tone] || window.PortBridgeTones.PILL.muted; },
    });
})();
