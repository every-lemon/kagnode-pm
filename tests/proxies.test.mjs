import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseHeaders,
  lines,
  proposedName,
  routeStatus,
} from "../web/proxies.js";
test("route state distinguishes active revisions from unpublished drafts", () => {
  assert.equal(routeStatus({ revision: 3, published: 3 }), "Published");
  assert.equal(
    routeStatus({ revision: 4, published: 3 }),
    "Unpublished changes",
  );
  assert.equal(routeStatus({ revision: 1, published: 0 }), "Draft");
});
test("header editing preserves colon values and rejects accidental duplicates", () => {
  assert.deepEqual(
    parseHeaders("X-Link: https://example.test:8443/a\nX-Empty:"),
    { "X-Link": "https://example.test:8443/a", "X-Empty": "" },
  );
  assert.throws(() => parseHeaders("bad header"));
  assert.throws(() => parseHeaders("X-Test: one\nx-test: two"));
});
test("domain names suggest valid identifiers without altering display domains", () => {
  assert.equal(proposedName("*.Example.COM"), "wildcard-example-com");
  assert.deepEqual(lines(" example.com\r\n\n app.example.com "), [
    "example.com",
    "app.example.com",
  ]);
  assert.ok(proposedName("a".repeat(200)).length <= 64);
});
