import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  audit,
  crackRecord,
  duplicateHashes,
  hashPassword,
  isUnsalted,
  summarize,
} from "../lib/audit.js";

const samplePath = fileURLToPath(new URL("../data/sample-hashes.json", import.meta.url));
const wordsPath = fileURLToPath(new URL("../data/common-passwords.txt", import.meta.url));
const sample = JSON.parse(await readFile(samplePath, "utf8"));
const words = (await readFile(wordsPath, "utf8")).split("\n").filter(Boolean);
const results = audit(sample.records, words);
const byUser = Object.fromEntries(results.map((r) => [r.user, r.password]));

test("hashPassword matches a known SHA-256 value", () => {
  assert.equal(
    hashPassword("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("a salt changes the hash", () => {
  assert.notEqual(hashPassword("password123"), hashPassword("password123", "x"));
});

test("unsalted weak password is guessed", () => {
  const record = { user: "t", salt: "", hash: hashPassword("password123") };
  assert.equal(crackRecord(record, words), "password123");
});

test("salted weak password is still guessed, using the record's own salt", () => {
  const record = { user: "t", salt: "pepper", hash: hashPassword("letmein", "pepper") };
  assert.equal(crackRecord(record, words), "letmein");
  // The same word with a different salt gives a different hash, so a table built
  // without the salt would miss this record.
  assert.notEqual(hashPassword("letmein", "pepper"), hashPassword("letmein"));
});

test("a long passphrase outside the word list is not guessed", () => {
  const record = { user: "t", salt: "", hash: hashPassword("correct horse battery staple") };
  assert.equal(crackRecord(record, words), null);
});

test("the sample file gives the expected results", () => {
  const cracked = Object.entries(byUser).filter(([, p]) => p !== null).sort();
  assert.deepEqual(cracked, [
    ["alice.reyes", "password123"],
    ["bob.nakamura", "Summer2024!"],
    ["dave.osei", "letmein"],
    ["frank.moreau", "qwerty"],
    ["grace.lin", "qwerty"],
    ["jamal.wright", "monkey"],
    ["keiko.tanaka", "shadow"],
    ["luis.ortega", "abc123"],
    ["noah.patel", "ninja"],
    ["olga.petrova", "shadow"],
    ["priya.raman", "welcome"],
    ["quinn.baker", "welcome"],
  ]);
});

test("the sample file leaves the strong passwords alone", () => {
  for (const user of ["carol.diaz", "erin.fischer", "hector.silva", "irene.kowalski", "maria.rossi"]) {
    assert.equal(byUser[user], null, `${user} should not be guessed`);
  }
});

test("summary counts the cracked and uncracked users", () => {
  const stats = summarize(results);
  assert.equal(stats.total, sample.records.length);
  assert.equal(stats.cracked, 12);
  assert.equal(stats.notCracked, 5);
  assert.equal(stats.cracked + stats.notCracked, stats.total);
});

test("summary reports shared passwords, including a salted one", () => {
  const stats = summarize(results);
  const shared = stats.reused.map((g) => `${g.password}:${g.users.join(",")}`).sort();
  assert.deepEqual(shared, [
    "qwerty:frank.moreau,grace.lin",
    "shadow:keiko.tanaka,olga.petrova",
    "welcome:priya.raman,quinn.baker",
  ]);
});

test("identical hashes reveal a shared password without guessing", () => {
  const duplicates = duplicateHashes(sample.records);
  assert.equal(duplicates.length, 1);
  assert.deepEqual(duplicates[0].users, ["priya.raman", "quinn.baker"]);
});

test("salted records never produce identical hashes", () => {
  const salted = sample.records.filter((r) => !isUnsalted(r));
  assert.ok(salted.length > 0);
  assert.equal(duplicateHashes(salted).length, 0);
});

test("every sample record is fictional and has a 64-character hex hash", () => {
  assert.match(sample.note, /FICTIONAL/);
  assert.match(sample.company, /fictional/i);
  for (const r of sample.records) {
    assert.match(r.hash, /^[0-9a-f]{64}$/, `${r.user} hash is not SHA-256 hex`);
    assert.ok(r.user && r.role, `${r.user} is missing a user name or role`);
  }
});

test("the sample has a mix of salted and unsalted records", () => {
  const unsalted = sample.records.filter(isUnsalted).length;
  assert.ok(unsalted > 0 && unsalted < sample.records.length, "the sample should show both cases");
});
