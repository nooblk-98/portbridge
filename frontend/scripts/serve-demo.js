#!/usr/bin/env node
// Serves frontend/demo/dist/ the way a static host does (`/clients` is
// clients/index.html), for trying the demo locally:
//
//   npm run build:demo && npm run serve:demo      then open http://127.0.0.1:43292
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const ROOT = path.join(__dirname, "../demo/dist");
const PORT = Number(process.env.DEMO_PORT || 43292);
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png",
  ".svg": "image/svg+xml", ".json": "application/json", ".woff2": "font/woff2", ".txt": "text/plain",
};

http.createServer((request, response) => {
  const { pathname } = new URL(request.url, "http://localhost");
  let file = path.normalize(path.join(ROOT, decodeURIComponent(pathname)));
  if (!file.startsWith(ROOT)) return response.writeHead(403).end();
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!fs.existsSync(file)) return response.writeHead(404).end("Not found");
  response.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream" });
  fs.createReadStream(file).pipe(response);
}).listen(PORT, "127.0.0.1", () => console.log(`Demo at http://127.0.0.1:${PORT}`));
