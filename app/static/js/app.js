
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
            qr: false
        },

        forms: {
            client: { name: '', address: '' },
            fwd: { port: '', target_port: '', protocol: 'both', client_ip: '', source_ip: '' }
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
            // Auto refresh every 10 seconds
            setInterval(() => this.loadData(), 10000);

            // Watch for theme changes
            this.$watch('isDarkMode', val => {
                localStorage.setItem('theme', val ? 'dark' : 'light');
                if (val) document.documentElement.classList.add('dark');
                else document.documentElement.classList.remove('dark');
            });

            // Initial theme set
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
            // Match IP from CIDR if needed, or exact match
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
            setTimeout(() => {
                this.toast.show = false;
            }, 3000);
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

        async createClient() {
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
                // Try to parse error
                try {
                    const data = await err.json();
                    this.showToast(data.description || 'Error creating client', 'error');
                } catch (e) {
                    this.showToast('Error creating client', 'error');
                }
            }
        },

        async deleteClient(name) {
            if (!confirm('Are you sure? This will delete the client and its keys.')) return;
            try {
                await fetch(`/api/clients/${name}`, { method: 'DELETE' }).then(this.checkAuth);
                this.showToast('Client deleted');
                this.loadData();
            } catch (err) {
                this.showToast('Error deleting client', 'error');
            }
        },

        async createForwarding() {
            try {
                const res = await fetch('/api/forwardings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.forms.fwd)
                }).then(this.checkAuth);

                this.showToast('Forwarding rule added! 🎉');
                this.modals.fwd = false;
                this.loadData();
            } catch (err) {
                try {
                    const data = await err.json();
                    this.showToast(data.description || 'Error creating rule', 'error');
                } catch (e) {
                    this.showToast('Error creating rule', 'error');
                }
            }
        },

        async deleteForwarding(port, proto) {
            if (!confirm('Remove this forwarding rule?')) return;
            try {
                // Encode the slash in port ranges if present
                const encodedPort = encodeURIComponent(port);
                await fetch(`/api/forwardings/${encodedPort}/${proto}`, { method: 'DELETE' }).then(this.checkAuth);
                this.showToast('Rule removed');
                this.loadData();
            } catch (err) {
                this.showToast('Error removing rule', 'error');
            }
        }
    }
}
