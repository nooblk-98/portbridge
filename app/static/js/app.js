// Assembles the dashboard's Alpine component, `app()`, from one piece per area.
//
// The pieces live in js/app/ and are loaded before this file, each registering a
// factory on window.PortBridgeFeatures. They share one object, so any piece can
// call another's methods through `this`. A name defined twice is an error, found
// as soon as the page loads rather than as a confusing bug later.
//
//   shell          navigation, theme, dialogs, toasts, data refresh, formatting
//   dashboard      statistics, the traffic chart, health and server gauges
//   clients        peer cards and adding, renaming and deleting peers
//   peerSettings   the peer settings dialog and per-route access
//   routes         the Routes page and the profile import notice
//   forwarding     port forwarding rules
//   updateNotice   the "update available" banner and popup

const FEATURES = ['shell', 'dashboard', 'clients', 'peerSettings', 'routes', 'forwarding', 'updateNotice'];

/** Merge the pieces into one object, keeping getters live and refusing duplicate names. */
function mergeFeatures(names, registry) {
    const merged = {};
    for (const name of names) {
        const factory = registry[name];
        if (typeof factory !== 'function') throw new Error(`Dashboard piece "${name}" is not loaded`);
        const descriptors = Object.getOwnPropertyDescriptors(factory());
        for (const key of Object.keys(descriptors)) {
            if (Object.prototype.hasOwnProperty.call(merged, key)) {
                throw new Error(`Dashboard piece "${name}" defines "${key}" a second time`);
            }
            Object.defineProperty(merged, key, descriptors[key]);
        }
    }
    return merged;
}

function app() {
    return mergeFeatures(FEATURES, window.PortBridgeFeatures || {});
}

// Lets `node --test` load the assembly without a browser.
if (typeof module !== 'undefined') module.exports = { FEATURES, mergeFeatures, app };
