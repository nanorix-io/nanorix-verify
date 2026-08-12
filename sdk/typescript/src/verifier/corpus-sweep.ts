/**
 * Run the published conformance corpus against the TypeScript verifier.
 *
 * The corpus is the interoperability contract. Until this existed, the
 * TypeScript verifier's agreement with the reference implementation was
 * asserted rather than checked, and the README had to say so.
 *
 * Each fixture ships a committed verdict in a `.expected.json` sibling. Three
 * things are compared against it, under the policy the fixture itself declares:
 * `valid`, `stage_reached`, and the full wire-form failure object. The prose
 * rendering of a failure is not compared, only the structured form, because
 * the prose may differ between implementations and the wire form may not.
 *
 *   node --experimental-strip-types corpus-sweep.ts <corpus-dir>
 *
 * Exit 0 = every fixture matched. Exit 1 = at least one disagreed, and every
 * disagreement is printed. Exit 2 = the corpus could not be read, which is a
 * failure rather than an empty pass.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, basename, dirname } from "node:path";
import { verifyAuditProof, type VerifierPolicy } from "./auditproof.js";

/** Every fixture in the corpus, sorted, excluding verdicts and the index. */
function collectFixtures(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        walk(p);
      } else if (
        name.endsWith(".json") &&
        !name.endsWith(".expected.json") &&
        name !== "index.json"
      ) {
        out.push(p);
      }
    }
  };
  walk(root);
  return out;
}

/**
 * A region or authority mismatch is only reachable under the matching pin. The
 * pin travels with the fixture rather than living in this harness, so every
 * implementation reads the same policy from the same place.
 */
function policyFromExpected(expected: Record<string, unknown>): VerifierPolicy {
  const pins = (expected.policy ?? {}) as Record<string, string | undefined>;
  return {
    requiredRegion: pins.required_region,
    requiredAuthorityId: pins.required_authority_id,
  };
}

/** Stable stringify so key order cannot make two equal objects compare unequal. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
    .join(",")}}`;
}

async function main(): Promise<number> {
  const root = process.argv[2];
  if (!root) {
    console.error("usage: corpus-sweep.ts <corpus-dir>");
    return 2;
  }
  let fixtures: string[];
  try {
    fixtures = collectFixtures(root);
  } catch (e) {
    console.error(`could not read corpus at ${root}: ${String(e)}`);
    return 2;
  }
  if (fixtures.length === 0) {
    console.error(`corpus at ${root} is empty; the sweep would pass vacuously`);
    return 2;
  }

  const failures: string[] = [];
  for (const fixture of fixtures) {
    const rel = relative(root, fixture);
    const sibling = join(
      dirname(fixture),
      `${basename(fixture, ".json")}.expected.json`,
    );
    let expected: Record<string, unknown>;
    try {
      expected = JSON.parse(readFileSync(sibling, "utf8")) as Record<string, unknown>;
    } catch {
      failures.push(`${rel}: no readable .expected.json sibling`);
      continue;
    }

    const proof = JSON.parse(readFileSync(fixture, "utf8")) as Record<string, unknown>;
    const result = await verifyAuditProof(proof, policyFromExpected(expected));

    if (result.valid !== expected.valid) {
      failures.push(`${rel}: valid — expected ${expected.valid}, got ${result.valid}`);
    }
    if (result.stage_reached !== expected.stage_reached) {
      failures.push(
        `${rel}: stage_reached — expected ${expected.stage_reached}, got ${result.stage_reached}`,
      );
    }
    const want = canonical(expected.failure_reason ?? null);
    const got = canonical(result.failure_reason ?? null);
    if (want !== got) {
      failures.push(`${rel}: failure_reason — expected ${want}, got ${got}`);
    }
  }

  if (failures.length > 0) {
    console.log(`  ${failures.length} disagreement(s) across ${fixtures.length} fixture(s):`);
    for (const f of failures.slice(0, 40)) console.log(`    ${f}`);
    if (failures.length > 40) console.log(`    ... and ${failures.length - 40} more`);
    return 1;
  }
  console.log(`  ${fixtures.length} fixtures, all matching their committed verdicts`);
  return 0;
}

main().then((code) => process.exit(code));
