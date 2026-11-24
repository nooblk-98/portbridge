// The Forwarding page: port forwarding rules.
(() => {
    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).forwarding = () => ({
        forwardings: [],
        forwardingsReady: false,
        forwardingError: '',

        async loadForwardings(requestId) {
            try {
                const response = await fetch('/api/forwardings').then(this.checkAuth);
                const data = await response.json();
                if (requestId !== this.dataRequestId) return;
                this.forwardings = data.items;
                this.forwardingsReady = true;
                this.forwardingError = '';
            } catch (error) {
                if (error.status === 401) return;
                const details = error instanceof Response ? await error.json().catch(() => null) : null;
                if (requestId === this.dataRequestId) {
                    this.forwardingError = details?.description || 'Could not load forwarding rules.';
                }
            }
        },

        openFwdModal() {
            this.forms.fwd = { port: '', target_port: '', protocol: 'both', client_ip: '', source_ip: '' };
            this.modals.fwd = true;
        },

        confirmDeleteForwarding(port, proto) {
            this.pendingDelete = { type: 'forwarding', name: null, port, proto };
            this.modals.confirmDeleteFwd = true;
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
    });
})();
