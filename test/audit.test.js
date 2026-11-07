import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { audit, hashPassword, crackRecord } from "../lib/audit.js";

const samplePath = fileURLToPath(new URL("../data/sample-hashes.json", import.meta.url));
const wordsPath = fileURLToPath(new URL("../data/common-passwords.txt", import.meta.url));
const sample = JSON.parse(await readFile(samplePath, "utf8"));
const words = (await readFile(wordsPath, "utf8")).split("\n").filter(Boolean);

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
  const results = Object.fromEntries(audit(sample.records, words).map((r) => [r.user, r.password]));
  assert.deepEqual(results, {
    alice: "password123",
    bob: "Summer2024!",
    carol: null,
    dave: "letmein",
    erin: null,
  });
});

test("every sample record is fictional and has a 64-character hex hash", () => {
  assert.match(sample.note, /FICTIONAL/);
  for (const r of sample.records) {
    assert.match(r.hash, /^[0-9a-f]{64}$/, `${r.user} hash is not SHA-256 hex`);
  }
});
