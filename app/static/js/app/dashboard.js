// The Dashboard page: live statistics, the traffic chart, health checks and server gauges.
(() => {
    const HISTORY_CACHE_MS = 30000;

    // Chart.js must not be wrapped by Alpine's reactive proxy, so it lives here.
    let trafficChart = null;

    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).dashboard = () => ({
        stats: null,
        statsError: '',
        history: null,
        historyError: '',
        historyCache: {},
        historyRange: '1h',
        historyRequestId: 0,
        historyRanges: [
            { id: '1h', label: '1 h' },
            { id: '24h', label: '24 h' },
            { id: '7d', label: '7 d' }
        ],
        statsTick: 0,

        /** Load the dashboard's numbers and chart; called whenever the page is shown. */
        showDashboard() {
            this.loadStats();
            this.loadHistory();
            this.$nextTick(() => { if (trafficChart) trafficChart.resize(); });
        },

        /**
         * Live numbers every 10 seconds while the dashboard is visible; the chart
         * refreshes about once a minute, like the server samples.
         */
        startDashboardPolling() {
            document.addEventListener('visibilitychange', () => {
                if (document.hidden || this.currentTab !== 'dashboard') return;
                this.loadStats();
                this.loadHistory();
                this.statsTick = 0;
            });
            setInterval(() => {
                if (document.hidden || this.currentTab !== 'dashboard') return;
                this.loadStats();
                this.statsTick += 1;
                if (this.statsTick % 6 === 0) this.loadHistory();
            }, 10000);
        },

        /** Redraw the chart in the new theme's colours. */
        onThemeChange() {
            if (trafficChart) this.renderTrafficChart(true);
        },

        /** `stroke-dasharray` for a ring that is `percent` full. */
        ringDash(percent) {
            const circumference = 2 * Math.PI * 50;
            const clamped = Math.max(0, Math.min(100, percent || 0));
            return `${((clamped / 100) * circumference).toFixed(1)} ${circumference.toFixed(1)}`;
        },

        /** Colour class for a gauge: green, then amber at `warnAt`, then red at `critAt`. */
        toneFor(percent, warnAt = 70, critAt = 90) {
            const { TONE } = window.PortBridgeTones;
            if (percent >= critAt) return TONE.crit;
            if (percent >= warnAt) return TONE.warn;
            return TONE.ok;
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
            const { TONE } = window.PortBridgeTones;
            if (this.peersTotal === 0) return TONE.warn;
            if (this.peersOnline === 0) return TONE.crit;
            return this.peersOnline === this.peersTotal ? TONE.ok : TONE.warn;
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
        get healthBadgeClass() { return window.PortBridgeTones.HEALTH_BADGE[this.healthStatus] || ''; },
        healthIconClass(status) { return window.PortBridgeTones.HEALTH_ICON[status] || ''; },

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
                this.statsError = '';
            } catch (error) {
                if (error.status !== 401) this.statsError = 'Could not refresh live statistics.';
            }
        },

        async loadHistory() {
            const requestId = ++this.historyRequestId;
            const range = this.historyRange;
            try {
                const response = await fetch(`/api/stats/history?range=${encodeURIComponent(range)}`).then(this.checkAuth);
                const history = await response.json();
                if (requestId !== this.historyRequestId) return;
                this.historyCache[range] = { history, fetchedAt: Date.now() };
                this.history = history;
                this.historyError = '';
                this.renderTrafficChart();
            } catch (error) {
                if (requestId === this.historyRequestId && error.status !== 401) {
                    this.historyError = 'Could not refresh traffic history.';
                }
            }
        },

        setHistoryRange(range) {
            if (this.historyRange === range) return;
            this.historyRange = range;
            this.historyError = '';
            const cached = this.historyCache[range];
            if (cached && Date.now() - cached.fetchedAt < HISTORY_CACHE_MS) {
                ++this.historyRequestId;
                this.history = cached.history;
                this.renderTrafficChart();
            } else {
                this.history = null;
                this.loadHistory();
            }
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
    });
})();
