// Checks that the dashboard component assembles from its pieces (js/app/*.js).
// Run: npm test
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SCRIPTS = path.join(__dirname, "../../app/static/js");

/** Load the pieces and app.js into a fake browser, as base.html does, and return its globals. */
function load() {
  const sandbox = {
    window: { location: { pathname: "/" }, PortBridgeTheme: { isDark: () => false } },
    module: { exports: {} },
  };
  sandbox.window.window = sandbox.window;
  vm.createContext(sandbox);
  const order = fs.readdirSync(path.join(SCRIPTS, "app")).sort();
  for (const file of order) {
    vm.runInContext(fs.readFileSync(path.join(SCRIPTS, "app", file), "utf8"), sandbox, { filename: file });
  }
  vm.runInContext(fs.readFileSync(path.join(SCRIPTS, "app.js"), "utf8") + "\nglobalThis.__app = { app, FEATURES, mergeFeatures };", sandbox);
  return sandbox;
}

test("every piece in the list is loaded, and every piece on disk is in the list", () => {
  const sandbox = load();
  const registered = Object.keys(sandbox.window.PortBridgeFeatures).sort();
  const listed = [...sandbox.__app.FEATURES].sort();
  assert.deepEqual(registered, listed);
});

test("assembles one component with the pieces' state and methods", () => {
  const component = load().__app.app();
  for (const name of ["currentTab", "clients", "forwardings", "stats", "routes", "updateRelease", "modals"]) {
    assert.ok(name in component, `state ${name}`);
  }
  for (const name of [
    "initApp", "loadData", "loadStats", "loadClients", "loadForwardings", "createClient",
    "createForwarding", "savePeerOptions", "buildRouteView", "checkForUpdate", "showToast",
    "executeDelete", "showDashboard", "startDashboardPolling", "onThemeChange", "startUpdateChecks", "updateRoutes",
  ]) {
    assert.equal(typeof component[name], "function", `method ${name}`);
  }
});

test("getters stay live instead of being evaluated once", () => {
  const component = load().__app.app();
  const descriptor = Object.getOwnPropertyDescriptor(component, "filteredClients");
  assert.equal(typeof descriptor.get, "function");
  // A different search gives a different answer from the same getter.
  component.clients = [{ name: "alpha", address: "10.0.0.2/24" }, { name: "beta", address: "10.0.0.3/24" }];
  component.searchClient = "";
  assert.equal(component.filteredClients.length, 2);
  component.searchClient = "alp";
  assert.deepEqual(component.filteredClients.map(client => client.name), ["alpha"]);
});

test("the start page follows the address", () => {
  const sandbox = load();
  sandbox.window.location.pathname = "/routes";
  assert.equal(sandbox.__app.app().currentTab, "routes");
  sandbox.window.location.pathname = "/nowhere";
  assert.equal(sandbox.__app.app().currentTab, "dashboard");
});

test("a name defined by two pieces is refused", () => {
  const { mergeFeatures } = load().__app;
  const registry = { one: () => ({ shared() {} }), two: () => ({ shared() {} }) };
  assert.throws(() => mergeFeatures(["one", "two"], registry), /two.*"shared".*second time/);
});

test("a missing piece is reported by name", () => {
  const { mergeFeatures } = load().__app;
  assert.throws(() => mergeFeatures(["ghost"], {}), /"ghost" is not loaded/);
});
