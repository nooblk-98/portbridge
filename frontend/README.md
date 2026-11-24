# Frontend build

The dashboard UI is server-rendered Jinja templates, Alpine.js and Tailwind CSS.
Only the stylesheet needs a build step. The built file
(`app/static/css/tailwind.css`) is committed, so running or packaging PortBridge
needs no Node.

## Layout

| Path | What |
| --- | --- |
| `app/templates/` | Jinja pages and `components/` partials |
| `app/static/js/` | Our own scripts (`app.js`, `login.js`, `route-access.js`, `theme.js`) |
| `app/static/css/style.css` | Hand-written component styles (`pb-*`) |
| `app/static/css/tailwind.css` | **Generated**. Do not edit by hand |
| `app/static/vendor/` | Vendored third-party bundles and their licences |
| `frontend/` | Tailwind config, input CSS and `package.json` |

## Changing styles

Use Tailwind utility classes in the templates. After adding or removing classes:

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
