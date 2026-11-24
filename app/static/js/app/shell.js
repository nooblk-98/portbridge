// The page frame: navigation, the theme, dialogs and toasts, data refresh and number formatting.
// Every dashboard page builds on this; see app.js for how the pieces fit together.
(() => {
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

    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).shell = () => ({
        currentTab: pageForPath(window.location.pathname),
        mobileMenuOpen: false,
        isDarkMode: window.PortBridgeTheme.isDark(),
        dataRequestId: 0,
        dataRefreshing: false,
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
                if (tab === 'dashboard') this.showDashboard();
            };
            this.$watch('currentTab', showPage);
            window.addEventListener('popstate', () => {
                this.currentTab = pageForPath(window.location.pathname);
            });
            showPage(this.currentTab);
            this.setupTooltips();

            const refreshData = () => {
                if (!document.hidden && !this.dataRefreshing) this.loadData();
            };
            refreshData();
            setInterval(refreshData, 30000);
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) refreshData();
            });

            this.startDashboardPolling();
            this.startUpdateChecks();

            // theme.js owns the stored choice and the <html> class; follow it.
            window.PortBridgeTheme.subscribe(dark => {
                this.isDarkMode = dark;
                this.onThemeChange();
            });
        },

        /** Tooltips open on hover and focus; Escape dismisses them without moving focus. */
        setupTooltips() {
            document.addEventListener('keydown', event => {
                if (event.key !== 'Escape') return;
                document.querySelectorAll('[data-tip]:hover, [data-tip]:focus-within')
                    .forEach(tip => { tip.dataset.dismissed = ''; });
            });
            const rearm = event => {
                const tip = event.target.closest && event.target.closest('[data-tip]');
                if (tip && !tip.contains(event.relatedTarget)) delete tip.dataset.dismissed;
            };
            document.addEventListener('mouseout', rearm);
            document.addEventListener('focusout', rearm);
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
            const requestId = ++this.dataRequestId;
            this.dataRefreshing = true;
            try {
                await Promise.all([this.loadClients(requestId), this.loadForwardings(requestId)]);
            } finally {
                if (requestId === this.dataRequestId) this.dataRefreshing = false;
            }
        },

        showToast(message, type = 'success') {
            this.toast.message = message;
            this.toast.type = type;
            this.toast.show = true;
            setTimeout(() => { this.toast.show = false; }, 3000);
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

        // ---- formatting -----------------------------------------------------------

        /** Cartoon avatar for a peer, seeded by its public key so it survives renames. */
        avatarFor(client) {
            const avatars = window.PortBridgeAvatar;
            return avatars ? avatars.dataUri(client.public_key || client.name) : '';
        },

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
    });
})();
