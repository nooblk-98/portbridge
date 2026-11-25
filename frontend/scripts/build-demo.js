#!/usr/bin/env node
// Builds the live demo: the real dashboard as plain static files, ready for
// Cloudflare Pages or any static host. Run from frontend/:
//
//   npm run build:demo        writes frontend/demo/dist/
//
// The pages are rendered once by the fixture server (examples/e2e_server.rs), then
// saved as files. In the browser, demo/demo.js answers the dashboard's API calls
// from sample data, so no server (and no WireGuard) is involved.
const fs = require("node:fs");
const path = require("node:path");
const { ROOT, PASSWORD, startServer } = require("./lib/server");

const PORT = process.env.E2E_PORT || "43291";
const BASE = `http://127.0.0.1:${PORT}`;
const OUT = path.join(ROOT, "frontend/demo/dist");

// URL path -> file the host serves it from (`/clients` is clients/index.html).
const PAGES = { "/": "index.html", "/clients": "clients/index.html", "/routes": "routes/index.html", "/forwarding": "forwarding/index.html" };

/** The newest released version in the changelog, shown instead of "0.0.0-dev". */
function latestVersion() {
  const text = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  return /^## \[(\d+\.\d+\.\d+)\]/m.exec(text)?.[1] ?? "1.0.0";
}

/** Point a rendered page at the demo: no update check, the released version, the fake API loaded first. */
function adapt(html, version) {
  const demoScripts = `<script>window.PORTBRIDGE_DEMO_VERSION=${JSON.stringify(version)};</script>\n    <script src="/static/js/demo.js?v=${version}"></script>\n    `;
  const firstScript = html.search(/<script\b/);
  if (firstScript < 0) throw new Error("A page has no script to put the demo before.");
  return (html.slice(0, firstScript) + demoScripts + html.slice(firstScript))
    .replace(/(<meta name="portbridge-update-check" content=")[^"]*(")/, "$1off$2")
    .replaceAll("0.0.0-dev", version);
}

async function get(pathname, cookie) {
  const response = await fetch(`${BASE}${pathname}`, { headers: cookie ? { Cookie: cookie } : {}, redirect: "manual" });
  if (!response.ok) throw new Error(`${pathname} answered ${response.status}`);
  return response;
}

function write(file, content) {
  const target = path.join(OUT, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

async function main() {
  const version = latestVersion();
  const stop = await startServer(PORT);
  try {
    fs.rmSync(OUT, { recursive: true, force: true });
    fs.cpSync(path.join(ROOT, "app/static"), path.join(OUT, "static"), { recursive: true });
    fs.copyFileSync(path.join(ROOT, "frontend/demo/demo.js"), path.join(OUT, "static/js/demo.js"));

    const login = await fetch(`${BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: PASSWORD }),
    });
    const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
    if (!cookie) throw new Error("Could not sign in to the demo server.");

    write("login/index.html", adapt(await (await get("/login")).text(), version));
    for (const [urlPath, file] of Object.entries(PAGES)) {
      write(file, adapt(await (await get(urlPath, cookie)).text(), version));
    }
    // One sample QR code: the demo shows it for every peer.
    const qr = Buffer.from(await (await get("/clients/home.png", cookie)).arrayBuffer());
    write("static/img/demo-qr.png", qr);

    // Cloudflare Pages reads these two files; other hosts ignore them.
    write("_headers", [
      "/*",
      "  X-Content-Type-Options: nosniff",
      "  Referrer-Policy: strict-origin-when-cross-origin",
      "  X-Frame-Options: DENY",
      "/static/*",
      "  Cache-Control: public, max-age=3600",
      "",
    ].join("\n"));
    write("robots.txt", "User-agent: *\nAllow: /\n");
    console.log(`Demo for PortBridge v${version} written to ${path.relative(ROOT, OUT)}/`);
  } finally {
    stop();
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
