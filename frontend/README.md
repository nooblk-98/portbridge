# Frontend build

The dashboard UI is server-rendered Jinja templates, Alpine.js and Tailwind CSS.
Only the stylesheet needs a build step. The built file
(`app/static/css/tailwind.css`) is committed, so running or packaging PortBridge
needs no Node.

## Layout

| Path | What |
| --- | --- |
| `app/templates/` | Jinja pages and `components/` partials |
| `app/static/js/` | Our own scripts (`login.js`, `route-access.js`, `theme.js`, `tones.js`, `updates.js`) |
| `app/static/js/app.js` and `app/static/js/app/` | The dashboard's Alpine component, in one piece per area (see below) |
| `app/static/css/tailwind.css` | **Generated**. Do not edit by hand |
| `app/static/vendor/` | Vendored third-party bundles and their licences |
| `frontend/` | Tailwind config, input CSS and `package.json` |

## The dashboard script

The dashboard is one Alpine component, `app()`, assembled in `app.js` from one file
per area in `app/static/js/app/`: `shell` (navigation, theme, dialogs, toasts, data
refresh, formatting), `dashboard`, `clients`, `peer-settings`, `routes`,
`forwarding` and `update-notice`. Each file registers a factory on
`window.PortBridgeFeatures`, and `app.js` merges them into one object, so a piece
can call another's methods through `this`. A name defined in two pieces is an
error at load time. To add an area, create a file, add its script tag to
`base.html` and its name to `FEATURES` in `app.js`.

## Changing styles

The whole UI is styled with Tailwind utility classes in the templates; there is no
hand-written stylesheet. A style that several templates share is written once in
`app/templates/components/ui.html` (a dictionary of class strings plus a few
macros). Classes that depend on state (a status colour, a health level) live in
`app/static/js/tones.js`, written out in full so the build can find them. The
theme colours that change with light and dark mode are CSS variables in
`frontend/src/tailwind.css`, exposed as `ui-*` and `db-*` colours in the config.

After adding or removing classes:

```sh
cd frontend
npm ci
npm run build:css      # or: npm run watch:css
```

Commit the regenerated `app/static/css/tailwind.css`. CI rebuilds it and fails if
the committed file is out of date.

The theme (the `primary` and `dark` colours, fonts and animations) lives in
`frontend/tailwind.config.js`.

## Browser tests

End-to-end tests drive the real dashboard in Chromium (Playwright) against
`examples/e2e_server.rs`: the actual server with fixture peers and a fake
WireGuard/firewall command runner, so nothing touches the host.

```sh
cd frontend
npm ci
npx playwright install chromium
npm run test:e2e          # starts the server itself (first run compiles it)
```

They run at a desktop (1280 × 800) and a phone (390 × 844) size and cover
sign-in, every page, the dialogs, adding and removing peers and rules, route
access, the theme, the footer and the mobile drawer. Tests find things by role
and text, never by CSS class, so they keep passing when the styling changes.

To prove a styling change did not alter how anything looks, compare screenshots
(baselines are local only, because font rendering differs between machines):

```sh
VISUAL=1 npx playwright test visual --update-snapshots   # on the old code
VISUAL=1 npx playwright test visual                      # on the new code
```

## README screenshots

The screenshots in `images/screenshots/` are generated from the demo data (the
same server the browser tests use), so they never show real peers and are easy to
refresh after a UI change:

```sh
cd frontend
npm run screenshots
```

It builds the demo server, opens each page at 1600 pixels wide, resizes the window
to fit the whole page, and writes the six images at 2000 pixels wide. The footer
shows the newest version in `CHANGELOG.md` rather than the development build's
`0.0.0-dev`.

## Live demo

`npm run build:demo` writes the real dashboard as static files to
`frontend/demo/dist/` (git-ignored), for Cloudflare Pages or any static host. The
pages are rendered once by the fixture server (`examples/e2e_server.rs`), and
`frontend/demo/demo.js` replaces `fetch` in the browser so the dashboard talks to
sample data instead of a server. Nothing is sent anywhere, and no WireGuard is
involved. Edits last for the browser tab.

Try it locally: `npm run build:demo && npm run serve:demo`, then open
http://127.0.0.1:43292.

To host it on Cloudflare Pages, connect the repository, choose the **`demo`**
branch (the Demo workflow rebuilds and publishes it on every change to the
dashboard), leave the build command empty and set the output directory to `/`.
If you add an API route to the server, add the same answer to `demo.js`.
