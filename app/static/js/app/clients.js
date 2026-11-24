// The Clients page: peer cards, search, and adding, renaming and deleting peers.
(() => {
    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).clients = () => ({
        clients: [],
        clientsReady: false,
        clientsError: '',
        clientForwardingsAvailable: true,

        searchClient: '',
        activeClient: null,

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

        async loadClients(requestId) {
            try {
                const clientsRes = await fetch('/api/clients').then(this.checkAuth);
                const clientsData = await clientsRes.json();
                if (requestId !== this.dataRequestId) return;
                this.clients = Array.isArray(clientsData.items) ? clientsData.items : [];
                this.clientForwardingsAvailable = clientsData.forwardings_available !== false;
                this.updateRoutes(clientsData);
                this.clientsReady = true;
                this.clientsError = '';
            } catch (error) {
                if (requestId === this.dataRequestId && error.status !== 401) {
                    this.clientsError = 'Could not refresh clients and routes.';
                }
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

        openClientModal() {
            this.forms.client = { name: '', address: '' };
            this.modals.client = true;
        },

        showQR(client) {
            this.activeClient = client;
            this.modals.qr = true;
        },

        openRenameModal(client) {
            this.forms.rename = { oldName: client.name, newName: client.name };
            this.modals.rename = true;
        },

        confirmDeleteClient(name) {
            this.pendingDelete = { type: 'client', name, port: null, proto: null };
            this.modals.confirmDelete = true;
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
    });
})();
