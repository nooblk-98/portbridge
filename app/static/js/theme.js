// Colour scheme handling shared by the dashboard and the sign-in page.
//
// Loaded synchronously in <head> so the right scheme is applied before first
// paint. Tailwind's `dark:` variants key off the `dark` class on <html>; the
// <meta name="color-scheme"> mirrors the choice so native UI (scrollbars, form
// controls) follows it too. With nothing stored, the system preference wins.
(() => {
    const KEY = 'theme';
    const root = document.documentElement;
    const meta = document.querySelector('meta[name="color-scheme"]');
    const system = matchMedia('(prefers-color-scheme: dark)');
    const listeners = new Set();

    const read = () => {
        try {
            const value = localStorage.getItem(KEY);
            return value === 'dark' || value === 'light' ? value : null;
        } catch {
            return null;
        }
    };
    const write = value => {
        try {
            if (value) localStorage.setItem(KEY, value);
            else localStorage.removeItem(KEY);
        } catch {
            // Site data is blocked: the choice still applies for this page view.
        }
    };

    let override = read();
    const isDark = () => (override ? override === 'dark' : system.matches);

    const apply = () => {
        root.classList.toggle('dark', isDark());
        if (meta) meta.content = override ?? 'light dark';
        listeners.forEach(listener => listener(isDark()));
    };

    window.PortBridgeTheme = {
        isDark,
        /** Switch to the opposite of what is rendered right now. */
        toggle() {
            const target = isDark() ? 'light' : 'dark';
            // Only pin a scheme that differs from the system; matching it again
            // means the user is undoing their override.
            const pinned = (target === 'dark') !== system.matches ? target : null;
            override = pinned;
            write(pinned);
            apply();
        },
        subscribe(listener) {
            listeners.add(listener);
            listener(isDark());
        },
    };

    system.addEventListener('change', apply);
    addEventListener('storage', event => {
        if (event.key === KEY || event.key === null) {
            override = read();
            apply();
        }
    });
    apply();
})();
