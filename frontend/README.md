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
