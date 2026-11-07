#!/usr/bin/env node
// Lab command: audits the bundled FICTIONAL sample hashes against a short word list.
// It only reads files in data/. It takes no file path, so it can't be pointed at
// other data by accident.
//
//   node cli.js

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { audit } from "./lib/audit.js";

const samplePath = fileURLToPath(new URL("./data/sample-hashes.json", import.meta.url));
const wordsPath = fileURLToPath(new URL("./data/common-passwords.txt", import.meta.url));

const sample = JSON.parse(await readFile(samplePath, "utf8"));
const words = (await readFile(wordsPath, "utf8")).split("\n").filter(Boolean);

const results = audit(sample.records, words);
let cracked = 0;
for (const r of results) {
  if (r.password !== null) {
    cracked++;
    console.log(`${r.user.padEnd(8)} cracked: "${r.password}"`);
  } else {
    console.log(`${r.user.padEnd(8)} not in the word list`);
  }
}
console.log(`\n${cracked} of ${results.length} sample passwords were guessed from ${words.length} words.`);
