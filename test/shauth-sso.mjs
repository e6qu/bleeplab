import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const shauthSource = process.env.SHAUTH_SOURCE_DIR;
const password = process.env.SHAUTH_BOOTSTRAP_ADMIN_PASSWORD;
const primaryState = process.env.BLEEPLAB_PRIMARY_STATE_DIR;
const secondaryState = process.env.BLEEPLAB_SECONDARY_STATE_DIR;
assert.ok(shauthSource, "SHAUTH_SOURCE_DIR is required");
assert.ok(password, "SHAUTH_BOOTSTRAP_ADMIN_PASSWORD is required");
assert.ok(primaryState, "BLEEPLAB_PRIMARY_STATE_DIR is required");
assert.ok(secondaryState, "BLEEPLAB_SECONDARY_STATE_DIR is required");

const playwrightURL = pathToFileURL(path.join(shauthSource, "node_modules/playwright/index.mjs"));
const { chromium } = await import(playwrightURL.href);
const browser = await chromium.launch({ headless: true });
const errors = [];
let loginVisits = 0;

try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("requestfailed", (request) => errors.push(`${request.url()}: ${request.failure()?.errorText ?? "request failed"}`));
  page.on("request", (request) => {
    const target = new URL(request.url());
    if (request.method() === "GET" && target.pathname === "/login" && target.origin === "http://localhost:48080") loginVisits += 1;
    if (target.hostname !== "localhost" && target.hostname !== "127.0.0.1" && !target.hostname.endsWith(".localhost")) {
      errors.push(`external runtime dependency: ${target.origin}${target.pathname}`);
    }
  });

  // A direct Bleeplab entry traverses the real Shauth authorization-code,
  // PKCE, login, automatic managed-application consent, and token exchange.
  await page.goto("http://127.0.0.1:18929/ui/");
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password" }).click();
  await page.waitForURL("http://127.0.0.1:18929/ui/");
  await page.getByText("admin", { exact: true }).waitFor();
  await page.getByText("admin@localhost.test", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Log out" }).waitFor();
  await assertSession(context, "http://127.0.0.1:18929", true);
  assert.equal(loginVisits, 1, "direct entry did not establish exactly one Shauth login");

  // The Shauth application catalog launches a second Bleeplab relying party.
  // The existing provider session grants it access without another login form.
  await page.goto("http://localhost:48080/apps");
  await page.locator('a[href="http://localhost:18930/ui/"]').click();
  await page.waitForURL("http://localhost:18930/ui/");
  await page.getByText("admin", { exact: true }).waitFor();
  await assertSession(context, "http://localhost:18930", true);
  assert.equal(loginVisits, 1, "catalog launch prompted for a second Shauth login");

  // Front-Channel Logout ignores an untrusted issuer but revokes the exact
  // provider session when Shauth supplies its issuer and sid coordinates.
  const secondarySID = readOnlySessionSID(secondaryState);
  let response = await context.request.get(
    `http://localhost:18930/auth/shauth/frontchannel-logout?iss=${encodeURIComponent("https://attacker.example")}&sid=${encodeURIComponent(secondarySID)}`,
  );
  assert.equal(response.status(), 200);
  await assertSession(context, "http://localhost:18930", true);
  response = await context.request.get(
    `http://localhost:18930/auth/shauth/frontchannel-logout?iss=${encodeURIComponent("http://localhost:49444")}&sid=${encodeURIComponent(secondarySID)}`,
  );
  assert.equal(response.status(), 200);
  await assertSession(context, "http://localhost:18930", false);

  // The provider SSO session remains active, so the revoked relying party can
  // establish a fresh local session without another credential prompt.
  await page.goto("http://localhost:18930/ui/");
  await page.waitForURL("http://localhost:18930/ui/");
  await page.getByText("admin", { exact: true }).waitFor();
  assert.equal(loginVisits, 1, "front-channel recovery prompted for credentials");

  // RP-Initiated Logout clears the initiating Bleeplab session before network
  // work, ends the shared Shauth session, returns to the initiating app, and
  // propagates signed Back-Channel Logout to both relying parties.
  await page.goto("http://127.0.0.1:18929/ui/");
  await page.getByRole("button", { name: "Log out" }).click();
  await page.waitForURL("http://127.0.0.1:18929/auth/signed-out");
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  await assertSession(context, "http://127.0.0.1:18929", false);
  await assertSession(context, "http://localhost:18930", false);
  await waitForLogoutClaim(primaryState);
  await waitForLogoutClaim(secondaryState);

  // Reloading the signed-out application stays signed out. Opening either RP
  // directly now reaches the one real Shauth login page instead of failing open.
  await page.reload();
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  await page.goto("http://localhost:18930/ui/");
  await page.waitForURL((url) => url.origin === "http://localhost:48080" && url.pathname === "/login");
  await page.locator("#username").waitFor();
  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}

async function assertSession(context, origin, authenticated) {
  const response = await context.request.get(`${origin}/internal/session`, { maxRedirects: 0 });
  if (!authenticated) {
    assert.equal(response.status(), 302, `${origin} retained an authenticated session`);
    const location = response.headers().location;
    assert.ok(location?.startsWith("/auth/shauth?return_to="), `${origin} did not fail closed: ${location}`);
    return;
  }
  assert.equal(response.status(), 200, `${origin} did not expose its verified session`);
  const session = await response.json();
  assert.deepEqual(session, {
    authenticated: true,
    name: "admin",
    email: "admin@localhost.test",
    role: "admin",
  });
}

function readOnlySessionSID(stateRoot) {
  const files = fs.readdirSync(path.join(stateRoot, "sessions")).filter((name) => name.endsWith(".json"));
  assert.equal(files.length, 1, `expected one active session in ${stateRoot}`);
  const session = JSON.parse(fs.readFileSync(path.join(stateRoot, "sessions", files[0]), "utf8"));
  assert.ok(session.sid, `session in ${stateRoot} omitted sid`);
  return session.sid;
}

async function waitForLogoutClaim(stateRoot) {
  const directory = path.join(stateRoot, "logout-claims");
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (fs.readdirSync(directory).some((name) => name.endsWith(".json"))) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail(`Shauth did not deliver signed Back-Channel Logout to ${stateRoot}`);
}
