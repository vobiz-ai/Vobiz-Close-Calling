#!/usr/bin/env node
/** Syntax-checks every JavaScript file and validates every JSON file. */
import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, extname } from "node:path";
import { execFileSync } from "node:child_process";

const SKIP = new Set(["node_modules", ".git", "coverage", "dist", "tmp"]);
const files = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
}
walk(".");

let failed = 0;

for (const f of files.filter((f) => extname(f) === ".js")) {
  try {
    execFileSync(process.execPath, ["--check", f], { stdio: "pipe" });
    console.log(`  ok    ${f}`);
  } catch (err) {
    console.error(`  FAIL  ${f}`);
    console.error(String(err.stderr || err.message).trim());
    failed++;
  }
}

for (const f of files.filter((f) => extname(f) === ".json")) {
  try {
    JSON.parse(readFileSync(f, "utf8"));
    console.log(`  ok    ${f}`);
  } catch (err) {
    console.error(`  FAIL  ${f} — ${err.message}`);
    failed++;
  }
}

if (failed) {
  console.error(`\n${failed} file(s) failed.`);
  process.exit(1);
}
console.log("\nAll files parse cleanly.");
