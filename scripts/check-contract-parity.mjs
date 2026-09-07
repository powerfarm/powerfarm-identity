import { readFile, readdir } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(await readFile(new URL("contracts/registry.json", root), "utf8"));
const migrationsDir = new URL("supabase/migrations/", root);
const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();
const sql = (await Promise.all(
  files.map((name) => readFile(new URL(name, migrationsDir), "utf8")),
)).join("\n");

const errors = [];

function lastMatch(pattern) {
  const matches = [...sql.matchAll(pattern)];
  return matches.at(-1) ?? null;
}

function sqlArray(kind, version) {
  const block = lastMatch(
    new RegExp(
      `when\\s+'${kind}'\\s+then\\s+case\\s+p_version([\\s\\S]*?)end`,
      "g",
    ),
  );
  if (!block) return null;
  const arm = [...block[1].matchAll(
    new RegExp(`when\\s+${version}\\s+then\\s+array\\[([^\\]]+)\\]`, "g"),
  )].at(-1);
  if (!arm) return null;
  return arm[1].split(",").map((item) => item.trim().replace(/^'|'$/g, ""));
}

for (const [kind, versions] of Object.entries(contract.required)) {
  for (const [version, keys] of Object.entries(versions)) {
    const extracted = sqlArray(kind, version);
    if (!extracted) {
      errors.push(`SQL is missing powerfarm_entity_contract('${kind}') version ${version}`);
      continue;
    }
    if (JSON.stringify(extracted) !== JSON.stringify(keys)) {
      errors.push(
        `${kind} v${version}: SQL [${extracted.join(", ")}] != registry.json [${keys.join(", ")}]`,
      );
    }
  }
}

const kindsCheck = lastMatch(
  /identities_kind_check[\s\S]{0,200}check\s*\(\s*kind\s+in\s*\(([^)]+)\)/gi,
);
if (!kindsCheck) {
  errors.push("could not find identities_kind_check");
} else {
  const kinds = [...kindsCheck[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  const expected = Object.keys(contract.required);
  if (JSON.stringify(kinds) !== JSON.stringify(expected)) {
    errors.push(`kind check [${kinds.join(", ")}] != registry.json [${expected.join(", ")}]`);
  }
}

if (contract.required.engine) {
  errors.push("engine is a qualifier on app, not a kind — remove it from required");
}

for (const [qualifier, spec] of Object.entries(contract.park.tenant_qualifier)) {
  for (const field of spec.requires) {
    if (!sql.includes(`'${field}'`) && !sql.includes(`"${field}"`)) {
      errors.push(`park tenant field ${qualifier}.${field} is not referenced in SQL`);
    }
  }
  if (!sql.includes(spec.place_park_type)) {
    errors.push(`park type ${spec.place_park_type} is not referenced in SQL`);
  }
}

if (errors.length) {
  console.error(`CONTRACT PARITY: FAIL\n- ${errors.join("\n- ")}`);
  process.exit(1);
}

const kinds = Object.keys(contract.required).length;
const versions = Object.values(contract.required).reduce(
  (n, item) => n + Object.keys(item).length,
  0,
);
console.log(`CONTRACT PARITY: PASS · ${kinds} kinds · ${versions} versions`);
