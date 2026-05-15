
function app() {
    return {
        currentTab: 'dashboard',
        mobileMenuOpen: false,
        isDarkMode: localStorage.getItem('theme') === 'dark',
        state: {},
        clients: [],
        forwardings: [],
        searchClient: '',
        activeClient: null,

        modals: {
            client: false,
            fwd: false,
            qr: false,
            rename: false,
            confirmDelete: false,
            confirmDeleteFwd: false,
        },

        forms: {
            client: { name: '', address: '' },
            fwd: { port: '', target_port: '', protocol: 'both', client_ip: '', source_ip: '' },
            rename: { oldName: '', newName: '' },
        },

        pendingDelete: { type: null, name: null, port: null, proto: null },

        loading: {
            createClient: false,
            createFwd: false,
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
                this.clients = clientsData.items;
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
