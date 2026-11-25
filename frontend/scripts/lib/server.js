// Starts the fixture server (examples/e2e_server.rs) for the scripts that need a
// real PortBridge to look at: the screenshots and the demo build.
const { spawn, execFileSync } = require("node:child_process");
const path = require("node:path");

const ROOT = path.join(__dirname, "../../..");
const PASSWORD = "e2e-password";

/** Build and start the server on `port`, wait until it answers, and return a function that stops it. */
async function startServer(port) {
  execFileSync("cargo", ["build", "--quiet", "--example", "e2e_server"], { cwd: ROOT, stdio: "inherit" });
  const server = spawn(path.join(ROOT, "target/debug/examples/e2e_server"), [], {
    cwd: ROOT,
    env: { ...process.env, E2E_PORT: String(port) },
    stdio: "ignore",
  });
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/login`)).ok) return () => server.kill();
    } catch {
      // Not listening yet.
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  server.kill();
  throw new Error("The demo server did not start.");
}

module.exports = { ROOT, PASSWORD, startServer };
