// @ts-check
// Shared test setup. Specs import `test` and `expect` from here, not from
// @playwright/test, so that no test ever reaches the real GitHub.
const base = require("@playwright/test");

const RELEASE_API = "https://api.github.com/repos/nooblk-98/portbridge/releases/latest";
// The e2e server is a development build, which reports 0.0.0-dev. A release with the
// same number is not newer, so it is what "nothing newer" looks like.
const RUNNING_VERSION = "0.0.0";

/** Release notes like the ones the release workflow publishes, plus hostile input. */
const NOTES = [
  "### Added",
  "",
  "- **A notice when a newer release exists.** It shows what changed and the upgrade",
  "  command, with `Remind me later` and `Ignore this version`.",
  "- Read the [guide](https://github.com/nooblk-98/portbridge#readme) first.",
  "",
  "### Fixed",
  "",
  "- Peers on `10.8.0.0/24` no longer drop out after a restart.",
  "",
  "A paragraph with <script>window.__pwned = 1</script> and [bad](javascript:window.__pwned=1) text.",
  "",
  "### Install or upgrade",
  "",
  "```sh",
  "curl -fsSL https://example.invalid/install.sh | sudo bash",
  "```",
  "",
  "**Full changelog**: https://github.com/nooblk-98/portbridge/compare/v1.4.0...v1.5.0",
].join("\n");

/** The body GitHub's "latest release" endpoint returns, for `version` like "1.5.0". */
function releaseBody(version, notes = NOTES) {
  return {
    tag_name: `v${version}`,
    html_url: `https://github.com/nooblk-98/portbridge/releases/tag/v${version}`,
    body: notes,
    published_at: "2026-11-24T10:00:00Z",
    draft: false,
    prerelease: false,
  };
}

/**
 * Answer the release lookup. Returns a counter of how many times it was asked.
 * @param {import('@playwright/test').Page} page
 * @param {string | { status: number } | 'offline'} latest a version, an HTTP failure or 'offline'
 */
async function mockRelease(page, latest, notes) {
  const calls = { count: 0 };
  await page.route(RELEASE_API, async route => {
    calls.count += 1;
    if (latest === "offline") return route.abort("failed");
    if (typeof latest === "object") {
      return route.fulfill({ status: latest.status, contentType: "application/json", body: "{}" });
    }
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(releaseBody(latest, notes)),
      headers: { "access-control-allow-origin": "*" },
    });
  });
  return calls;
}

const test = base.test.extend({
  // Every test starts with GitHub reporting nothing newer than what is running.
  page: async ({ page }, use) => {
    await mockRelease(page, RUNNING_VERSION);
    await use(page);
  },
});

module.exports = { test, expect: base.expect, mockRelease, releaseBody, RUNNING_VERSION, NOTES };
