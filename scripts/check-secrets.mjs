#!/usr/bin/env node
/**
 * Refuses to let a credential into the repository: Vobiz Auth IDs and tokens,
 * real phone numbers, tunnel hostnames, private keys.
 *
 * A sibling project once shipped live credentials in `.env.example`, which its
 * .gitignore did not cover. This scan does not trust the ignore file.
 */
import { readdirSync, statSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SKIP = new Set(["node_modules", ".git", "coverage", "dist", "tmp", "data"]);

// Vendored bundles and lockfiles are full of long random-looking strings;
// scanning them trains people to ignore real hits.
const SKIP_FILES = [
  /(^|[/\\])public[/\\]lib[/\\]/,
  /(^|[/\\])\.env$/,
  /(^|[/\\])package-lock\.json$/,
  /(^|[/\\])scripts[/\\]check-secrets\.mjs$/,
];

const RULES = [
  { name: "Vobiz auth ID", re: /\b(?:MA|SA)_[A-Z0-9]{8,}\b/g, allow: [/^(?:MA|SA)_TEST\d{4}$/] },
  { name: "Vobiz auth token", re: /\b[A-Za-z0-9]{48,}\b/g },
  {
    name: "real phone number",
    re: /\+\d{11,15}\b/g,
    // Test fakes: +9100000000NN, +91[79]000000NNN, +8600000000NN and fictional +1555 numbers.
    allow: [/^\+9100000000\d\d$/, /^\+91[79]0{6}\d{3}$/, /^\+860{9}\d{2}$/, /^\+1555\d{7}$/],
  },
  { name: "Close API key", re: /\bapi_[A-Za-z0-9.]{20,}\b/g, allow: [/^api_TEST/] },
  { name: "ephemeral tunnel hostname", re: /[a-z0-9-]+\.(?:trycloudflare\.com|ngrok(?:-free)?\.(?:io|app|dev))/g },
  { name: "private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
];

const PLACEHOLDER = /X{4,}|REPLACE|EXAMPLE|YOUR_|<[a-z ]+>/i;

const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(".");

let found = 0;
for (const f of files) {
  if (SKIP_FILES.some((re) => re.test(f))) continue;
  let text;
  try { text = readFileSync(f, "utf8"); } catch { continue; }
  if (text.indexOf(String.fromCharCode(0)) !== -1) continue;
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      const hit = m[0];
      if (PLACEHOLDER.test(hit)) continue;
      if (rule.allow && rule.allow.some((a) => a.test(hit))) continue;
      const line = text.slice(0, m.index).split("\n").length;
      console.error(`  ${f}:${line}  possible ${rule.name}: ${hit.slice(0, 14)}…`);
      found++;
    }
  }
}

if (found) {
  console.error(`\n${found} possible secret(s) found. Remove them before committing.`);
  process.exit(1);
}
console.log("No credentials, tokens, or real phone numbers found.");
