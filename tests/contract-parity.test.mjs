import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);

test("registry.json has no engine kind and app v2 requires place plus qualifier", async () => {
  const contract = JSON.parse(await readFile(new URL("contracts/registry.json", root), "utf8"));
  assert.equal(contract.required.engine, undefined);
  assert.deepEqual(contract.required.place["1"], ["slug", "title", "owner", "machine", "path", "park_type"]);
  assert.ok(contract.required.app["2"].includes("place"));
  assert.ok(contract.required.app["2"].includes("qualifier"));
  assert.equal(contract.park.tenant_qualifier.engine.place_park_type, "engine-park");
  assert.equal(contract.park.tenant_qualifier.app.place_park_type, "app-park");
  assert.equal(contract.current.app, 2);
});

test("check-contract-parity passes against the committed SQL", () => {
  const script = fileURLToPath(new URL("scripts/check-contract-parity.mjs", root));
  const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /CONTRACT PARITY: PASS/);
});
