// Unit tests for the pure parts of app/static/js/updates.js. Run: npm test
const test = require("node:test");
const assert = require("node:assert/strict");
const updates = require("../../app/static/js/updates.js");

const RELEASE = {
  version: "1.5.0",
  url: "https://github.com/nooblk-98/portbridge/releases/tag/v1.5.0",
  notes: "",
  publishedAt: "",
};
const HOUR = 60 * 60 * 1000;

test("parses release numbers with or without a leading v", () => {
  assert.deepEqual(updates.parseVersion("v1.4.2"), [1, 4, 2]);
  assert.deepEqual(updates.parseVersion("1.10.0"), [1, 10, 0]);
  assert.deepEqual(updates.parseVersion("1.4.2-rc1"), [1, 4, 2]);
  for (const bad of ["", "latest", "1.4", null, undefined, "v1"]) {
    assert.equal(updates.parseVersion(bad), null, String(bad));
  }
});

test("compares numerically, not as text", () => {
  assert.equal(updates.compareVersions("1.4.2", "1.4.10"), -1);
  assert.equal(updates.compareVersions("1.10.0", "1.9.9"), 1);
  assert.equal(updates.compareVersions("v2.0.0", "1.99.99"), 1);
  assert.equal(updates.compareVersions("1.4.2", "v1.4.2"), 0);
  assert.equal(updates.compareVersions("nonsense", "1.4.2"), 0);
});

test("a release is newer only when its number is higher", () => {
  assert.ok(updates.isNewer("1.5.0", "1.4.2"));
  assert.ok(!updates.isNewer("1.4.2", "1.4.2"));
  assert.ok(!updates.isNewer("1.4.1", "1.4.2"));
  assert.ok(!updates.isNewer("nonsense", "1.4.2"));
});

test("shouldNotify announces a newer release", () => {
  assert.ok(updates.shouldNotify(RELEASE, "1.4.2", {}, 0));
  assert.ok(!updates.shouldNotify(RELEASE, "1.5.0", {}, 0), "already running it");
  assert.ok(!updates.shouldNotify(null, "1.4.2", {}, 0));
});

test("remind me later hides the notice until the reminder time", () => {
  const choice = { remindAt: 10 * HOUR };
  assert.ok(!updates.shouldNotify(RELEASE, "1.4.2", choice, 9 * HOUR));
  assert.ok(updates.shouldNotify(RELEASE, "1.4.2", choice, 10 * HOUR + 1));
});

test("ignoring a version hides it, but a newer release is announced again", () => {
  const choice = { ignored: "1.5.0" };
  assert.ok(!updates.shouldNotify(RELEASE, "1.4.2", choice, 0));
  assert.ok(updates.shouldNotify({ ...RELEASE, version: "1.5.1" }, "1.4.2", choice, 0));
  assert.ok(!updates.shouldNotify({ ...RELEASE, version: "1.4.9" }, "1.4.2", { ignored: "1.5.0" }, 0));
});

test("the cached release is reused while fresh and refreshed after", async () => {
  const store = new Map();
  global.localStorage = {
    getItem: key => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => store.set(key, value),
  };
  let calls = 0;
  const reply = tag => async () => {
    calls += 1;
    return {
      ok: true,
      json: async () => ({
        tag_name: tag,
        html_url: `https://github.com/nooblk-98/portbridge/releases/tag/${tag}`,
        body: "notes",
        published_at: "2026-01-01T00:00:00Z",
      }),
    };
  };

  const first = await updates.latestRelease({ fetchImpl: reply("v1.5.0"), now: 0 });
  assert.equal(first.version, "1.5.0");
  const again = await updates.latestRelease({ fetchImpl: reply("v9.9.9"), now: 5 * HOUR });
  assert.equal(again.version, "1.5.0", "still fresh");
  assert.equal(calls, 1);
  const refreshed = await updates.latestRelease({ fetchImpl: reply("v1.6.0"), now: 7 * HOUR });
  assert.equal(refreshed.version, "1.6.0");

  const offline = await updates.latestRelease({
    fetchImpl: async () => { throw new Error("offline"); },
    now: 20 * HOUR,
  });
  assert.equal(offline.version, "1.6.0", "falls back to the last copy");
  delete global.localStorage;
});

test("a bad response or a foreign link is not trusted", async () => {
  global.localStorage = { getItem: () => null, setItem() {} };
  const bad = await updates.latestRelease({
    fetchImpl: async () => ({ ok: true, json: async () => ({ tag_name: "latest" }) }),
    now: 0,
  });
  assert.equal(bad, null);
  const down = await updates.latestRelease({ fetchImpl: async () => ({ ok: false }), now: 0 });
  assert.equal(down, null);
  const foreign = await updates.latestRelease({
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ tag_name: "v1.5.0", html_url: "https://evil.example/x", body: "" }),
    }),
    now: 0,
  });
  assert.equal(foreign.url, "https://github.com/nooblk-98/portbridge/releases");
  delete global.localStorage;
});
