// Tailwind classes for styling that depends on state (a status, a health level,
// a load tone). The names are written out in full, never built from pieces, so
// the Tailwind build can find them in this file.
(() => {
    /** Colours a ring or a meter bar, which both paint with `currentColor`. */
    const TONE = {
        ok: 'text-db-ok',
        warn: 'text-db-warn',
        crit: 'text-db-crit',
    };

    /** Overall health badge on the dashboard. */
    const HEALTH_BADGE = {
        ok: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/[0.18] dark:text-emerald-400',
        warn: 'bg-amber-100 text-amber-700 dark:bg-amber-500/[0.18] dark:text-amber-400',
        fail: 'bg-rose-100 text-rose-700 dark:bg-rose-500/[0.18] dark:text-rose-400',
    };

    /** Icon of one health check. */
    const HEALTH_ICON = {
        ok: 'text-db-ok',
        warn: 'text-db-warn',
        fail: 'text-db-crit',
    };

    /** Status pills on the Routes page. */
    const PILL = {
        ok: 'border-green-200 bg-green-100 text-green-900 dark:border-emerald-800 dark:bg-emerald-900 dark:text-emerald-200',
        warn: 'border-amber-200 bg-amber-100 text-amber-900 dark:border-amber-800 dark:bg-amber-900 dark:text-amber-200',
        danger: 'border-red-200 bg-red-100 text-red-900 dark:border-red-800 dark:bg-red-900 dark:text-red-200',
        muted: 'border-slate-300 bg-slate-200 text-slate-700 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200',
    };

    window.PortBridgeTones = { TONE, HEALTH_BADGE, HEALTH_ICON, PILL };
})();
