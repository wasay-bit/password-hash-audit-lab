#!/usr/bin/env node
// Lab command: audits the bundled FICTIONAL sample hashes against a short word list.
// It only reads files in data/. It takes no file path, so it can't be pointed at
// other data by accident.
//
//   node cli.js

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { audit, summarize, duplicateHashes, isUnsalted } from "./lib/audit.js";

const samplePath = fileURLToPath(new URL("./data/sample-hashes.json", import.meta.url));
const wordsPath = fileURLToPath(new URL("./data/common-passwords.txt", import.meta.url));

const sample = JSON.parse(await readFile(samplePath, "utf8"));
const words = (await readFile(wordsPath, "utf8")).split("\n").filter(Boolean);
const records = sample.records;

const results = audit(records, words);
const stats = summarize(results);
const duplicates = duplicateHashes(records);
const recordFor = new Map(records.map((r) => [r.user, r]));

console.log(`Company: ${sample.company} (fictional data)\n`);

console.log("Guessed from the word list:");
for (const r of results) {
  const record = recordFor.get(r.user);
  const saltNote = isUnsalted(record) ? "no salt" : "salted";
  if (r.password !== null) {
    console.log(`  ${r.user.padEnd(16)} ${saltNote.padEnd(8)} "${r.password}"`);
  }
}

console.log("\nNot guessed:");
for (const r of results) {
  if (r.password === null) {
    const record = recordFor.get(r.user);
    const saltNote = isUnsalted(record) ? "no salt" : "salted";
    console.log(`  ${r.user.padEnd(16)} ${saltNote.padEnd(8)} (outside the word list)`);
  }
}

if (stats.reused.length > 0) {
  console.log("\nPasswords shared by more than one user:");
  for (const group of stats.reused) {
    console.log(`  "${group.password}" used by ${group.users.join(", ")}`);
  }
}

if (duplicates.length > 0) {
  console.log("\nIdentical hashes (same password, no salt):");
  for (const group of duplicates) {
    console.log(`  ${group.users.join(" and ")}`);
  }
}

const unsaltedCracked = results.filter(
  (r) => r.password !== null && isUnsalted(recordFor.get(r.user)),
).length;
const saltedCracked = results.filter(
  (r) => r.password !== null && !isUnsalted(recordFor.get(r.user)),
).length;

console.log(`\n${stats.cracked} of ${stats.total} passwords were guessed from ${words.length} words.`);
console.log(`  ${unsaltedCracked} of them were stored without a salt, ${saltedCracked} with one.`);
console.log("Salting did not save the weak passwords: the attacker tries each word with that user's salt.");
