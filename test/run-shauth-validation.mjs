import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";

const required = (name) => {
  const value = process.env[name]?.trim();
  assert.ok(value, `${name} is required`);
  return value;
};

const shauthSource = required("SHAUTH_SOURCE_DIR");
const shauthURL = required("SHAUTH_URL").replace(/\/$/, "");
const validatorToken = required("SHAUTH_VALIDATOR_TOKEN");
const validationUsername = required("SHAUTH_VALIDATION_USERNAME");
const validationEmail = required("SHAUTH_VALIDATION_EMAIL");
const releaseRevision = required("APPLICATION_RELEASE_REVISION");
assert.match(releaseRevision, /^(?:[0-9a-f]{12,64}|sha256:[0-9a-f]{64})$/);

const primary = {
  managed_app_id: "bleeplab-primary",
  app_slug: "bleeplab-primary",
  app_name: "Bleeplab primary",
  oidc_client_id: "bleeplab-primary",
  launch_url: "http://127.0.0.1:18929/ui/",
  validation_url: "http://127.0.0.1:18929/auth/validation",
  logout_bridge_url: "http://127.0.0.1:18929/auth/shauth/logout/complete",
  signed_out_url: "http://127.0.0.1:18929/auth/signed-out",
  release_revision: releaseRevision,
};
const secondary = {
  managed_app_id: "bleeplab-secondary",
  app_slug: "bleeplab-secondary",
  app_name: "Bleeplab secondary",
  oidc_client_id: "bleeplab-secondary",
  launch_url: "http://localhost:18930/ui/",
  validation_url: "http://localhost:18930/auth/validation",
  logout_bridge_url: "http://localhost:18930/auth/shauth/logout/complete",
  signed_out_url: "http://localhost:18930/auth/signed-out",
  release_revision: releaseRevision,
};

function assertApplicationContract(app) {
  const launch = new URL(app.launch_url);
  const bridge = new URL(app.logout_bridge_url);
  const signedOut = new URL(app.signed_out_url);
  assert.equal(bridge.origin, launch.origin, `${app.app_slug} logout bridge must use the application origin`);
  assert.equal(bridge.pathname, "/auth/shauth/logout/complete", `${app.app_slug} logout bridge path is invalid`);
  assert.equal(bridge.search, "", `${app.app_slug} logout bridge must not contain a query`);
  assert.equal(bridge.hash, "", `${app.app_slug} logout bridge must not contain a fragment`);
  assert.equal(signedOut.origin, launch.origin, `${app.app_slug} signed-out page must use the application origin`);
  assert.notEqual(signedOut.href, bridge.href, `${app.app_slug} protocol bridge and user-facing signed-out page must be distinct`);
}

assertApplicationContract(primary);
assertApplicationContract(secondary);

for (const direction of ["from_app", "from_shauth"]) {
  const bootstrapResponse = await fetch(`${shauthURL}/internal/validator/browser-bootstraps`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${validatorToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ next: [direction === "from_shauth" ? "/apps" : "/", "/"] }),
  });
  assert.equal(bootstrapResponse.status, 200, `Shauth bootstrap request returned ${bootstrapResponse.status}`);
  const bootstrap = await bootstrapResponse.json();
  assert.equal(Array.isArray(bootstrap.urls) ? bootstrap.urls.length : 0, 2, "Shauth did not issue exactly two browser bootstraps");

  const job = {
    id: `bleeplab-${direction}`,
    ...primary,
    direction,
    shauth_url: shauthURL,
    bootstrap_urls: bootstrap.urls,
    witness: secondary,
  };
  const result = spawnSync(process.execPath, [path.join(shauthSource, "validator/validate.mjs")], {
    cwd: shauthSource,
    encoding: "utf8",
    input: JSON.stringify(job),
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      NODE_PATH: process.env.NODE_PATH ?? "",
      PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH ?? "",
      SHAUTH_VALIDATION_USERNAME: validationUsername,
      SHAUTH_VALIDATION_EMAIL: validationEmail,
    },
    timeout: 8 * 60 * 1000,
  });
  assert.equal(result.status, 0, `Shauth validator process failed for ${direction}: ${result.stderr}`);
  const outcome = JSON.parse(result.stdout);
  assert.deepEqual(outcome, { status: "passed", failure: "" }, `${direction} validation failed: ${outcome.failure}`);
  process.stdout.write(`Bleeplab ${direction} Shauth lifecycle passed.\n`);
}
