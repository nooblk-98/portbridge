// @ts-check
const { expect } = require("@playwright/test");

const PASSWORD = "e2e-password";

/** Narrower than the `md` breakpoint, where the sidebar becomes a drawer. */
const isMobile = page => (page.viewportSize()?.width ?? 1280) < 768;

/** Fill in the sign-in form. Pass `{ visit: false }` when already on the sign-in page. */
async function signIn(page, password = PASSWORD, { visit = true } = {}) {
  if (visit) await page.goto("/login");
  await page.getByPlaceholder("Enter admin password").fill(password);
  await page.getByRole("button", { name: "Sign In" }).click();
}

/** Open a page by its URL and wait until its heading is on screen. */
async function openPage(page, path, heading) {
  await page.goto(path);
  await expect(page.getByRole("heading", { level: 2, name: heading })).toBeVisible();
}

/** Use the navigation like a person would: the sidebar, or the drawer on a phone. */
async function navigateTo(page, label) {
  if (isMobile(page)) {
    await page.getByRole("button", { name: "Open navigation menu" }).click();
    await page.locator("#mobile-menu").getByRole("link", { name: label }).click();
  } else {
    await page.locator("aside").getByRole("link", { name: label }).click();
  }
}

/** Dismiss any "import the updated profile" banner a test caused. */
async function clearImportNotices(page) {
  const banner = page.getByRole("status").filter({ hasText: "to import" });
  while (await banner.first().isVisible().catch(() => false)) {
    const all = banner.getByRole("button", { name: "Mark all as imported" });
    const button = (await all.isVisible().catch(() => false))
      ? all
      : banner.getByRole("button", { name: /Mark .* as imported/ }).first();
    await button.click();
    await page.waitForTimeout(250);
  }
}

/** The page must never scroll sideways. */
async function expectNoHorizontalScroll(page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow, "horizontal overflow in px").toBeLessThanOrEqual(0);
}

/**
 * The average colour of a region of the page, as [r, g, b] from 0 to 255, read
 * from a screenshot so it includes everything painted there.
 * @param {import('@playwright/test').Page} page
 */
async function averageColor(page, clip) {
  const shot = (await page.screenshot({ clip })).toString("base64");
  return page.evaluate(async source => {
    const image = new Image();
    image.src = `data:image/png;base64,${source}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.width;
    canvas.height = image.height;
    const context = /** @type {CanvasRenderingContext2D} */ (canvas.getContext("2d"));
    context.drawImage(image, 0, 0);
    const { data } = context.getImageData(0, 0, canvas.width, canvas.height);
    const total = [0, 0, 0];
    for (let index = 0; index < data.length; index += 4) {
      total[0] += data[index];
      total[1] += data[index + 1];
      total[2] += data[index + 2];
    }
    const pixels = data.length / 4;
    return total.map(sum => Math.round(sum / pixels));
  }, shot);
}

/** Collect console errors and failed requests until `stop()` is called. */
function watchForProblems(page) {
  const problems = [];
  page.on("pageerror", error => problems.push(`page error: ${error.message}`));
  page.on("console", message => {
    if (message.type() === "error") problems.push(`console: ${message.text()}`);
  });
  page.on("response", response => {
    if (response.status() >= 400 && new URL(response.url()).origin === new URL(page.url() || "http://x").origin) {
      problems.push(`${response.status()} ${response.url()}`);
    }
  });
  return problems;
}

module.exports = {
  PASSWORD,
  isMobile,
  signIn,
  openPage,
  navigateTo,
  clearImportNotices,
  expectNoHorizontalScroll,
  averageColor,
  watchForProblems,
};
