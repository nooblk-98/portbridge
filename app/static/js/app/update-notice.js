// The "update available" banner and its changelog popup (the lookup itself is in updates.js).
(() => {
    (window.PortBridgeFeatures = window.PortBridgeFeatures || {}).updateNotice = () => ({
        // A newer release to announce, or null (see updates.js).
        updateRelease: null,
        updateOpen: false,
        updateTab: 'install',
        updateCopied: false,
        currentVersion: '',

        /** Check for a release shortly after loading, then every half hour (the answer is cached for hours, so this is rarely a request). */
        startUpdateChecks() {
            setTimeout(() => this.checkForUpdate(), 1500);
            setInterval(() => this.checkForUpdate(), 30 * 60 * 1000);
        },

        /** Ask GitHub for the newest release and announce it unless it was ignored or snoozed. */
        async checkForUpdate() {
            const updates = window.PortBridgeUpdates;
            const meta = name => document.querySelector(`meta[name="${name}"]`)?.content;
            if (!updates || meta('portbridge-update-check') !== 'on') return;
            this.currentVersion = meta('portbridge-version') || '';
            const release = await updates.latestRelease();
            this.updateRelease = updates.shouldNotify(release, this.currentVersion) ? release : null;
        },

        get updateCommand() {
            return window.PortBridgeUpdates.COMMANDS[this.updateTab] || '';
        },

        get updateSubtitle() {
            const published = this.updateRelease?.publishedAt
                ? new Date(this.updateRelease.publishedAt).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })
                : '';
            return [published && `Released ${published}`, `You are running v${this.currentVersion}`].filter(Boolean).join(' \u00b7 ');
        },

        openUpdate() {
            if (!this.updateRelease) return;
            this.lastFocusedElement = document.activeElement;
            this.updateCopied = false;
            this.updateOpen = true;
            this.$nextTick(() => {
                this.$refs.updateNotes.replaceChildren(window.PortBridgeUpdates.renderNotes(this.updateRelease.notes));
                this.$refs.updateDialog.focus();
            });
        },

        closeUpdate() {
            if (!this.updateOpen) return;
            this.updateOpen = false;
            const target = this.lastFocusedElement;
            this.lastFocusedElement = null;
            if (target && typeof target.focus === 'function') target.focus();
        },

        remindLater() {
            window.PortBridgeUpdates.remindLater();
            this.dismissUpdate('We will remind you again tomorrow.');
        },

        ignoreUpdate() {
            const version = this.updateRelease?.version;
            window.PortBridgeUpdates.ignore(version);
            this.dismissUpdate(`Ignoring v${version}. You will hear about the next release.`);
        },

        dismissUpdate(message) {
            this.updateOpen = false;
            this.updateRelease = null;
            this.showToast(message);
        },

        /** Copy the upgrade command; plain-HTTP dashboards have no clipboard API, so fall back. */
        async copyUpdateCommand() {
            const text = this.updateCommand;
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(text);
                } else {
                    const area = document.createElement('textarea');
                    area.value = text;
                    area.setAttribute('readonly', '');
                    area.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
                    document.body.append(area);
                    area.select();
                    const copied = document.execCommand('copy');
                    area.remove();
                    if (!copied) throw new Error('copy failed');
                }
                this.updateCopied = true;
                setTimeout(() => { this.updateCopied = false; }, 2000);
            } catch {
                this.showToast('Could not copy. Select the command and copy it.', 'error');
            }
        },
    });
})();
