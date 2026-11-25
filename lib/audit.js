// Hash audit: checks which passwords in a lab file can be guessed from a short
// word list. Lab use only. It reads the bundled sample file, and it doesn't
// connect to any login system.
//
// A hash is sha256(salt + password), written as hex. The salt is a short
// string added before the password. A salt stops one precomputed table from
// working for every user at once. Real systems should use a slow password
// hash such as scrypt, bcrypt, or argon2. SHA-256 is fast on purpose here so
// the lab runs quickly.

import { createHash } from "node:crypto";

export function hashPassword(password, salt = "") {
  return createHash("sha256").update(salt + password, "utf8").digest("hex");
}

// Returns the word that matches the record's hash, or null if none match.
export function crackRecord(record, words) {
  for (const word of words) {
    if (hashPassword(word, record.salt) === record.hash) return word;
  }
  return null;
}

// Runs crackRecord on every record. Returns one result per user.
export function audit(records, words) {
  return records.map((record) => ({
    user: record.user,
    password: crackRecord(record, words),
  }));
}

// Counts the results and finds passwords that more than one user chose.
// A reused password matters even when it is strong, because one leak exposes
// every account that shares it.
export function summarize(results) {
  const cracked = results.filter((r) => r.password !== null);
  const byPassword = new Map();
  for (const r of cracked) {
    if (!byPassword.has(r.password)) byPassword.set(r.password, []);
    byPassword.get(r.password).push(r.user);
  }
  const reused = [...byPassword.entries()]
    .filter(([, users]) => users.length > 1)
    .map(([password, users]) => ({ password, users }));
  return {
    total: results.length,
    cracked: cracked.length,
    notCracked: results.length - cracked.length,
    reused,
  };
}

// Finds records with exactly the same hash. Without a salt, the same password
// gives the same hash, so a match reveals that two people share a password
// before any guessing happens. With per-user salts, hashes never match.
export function duplicateHashes(records) {
  const byHash = new Map();
  for (const r of records) {
    if (!byHash.has(r.hash)) byHash.set(r.hash, []);
    byHash.get(r.hash).push(r.user);
  }
  return [...byHash.values()]
    .filter((users) => users.length > 1)
    .map((users) => ({ users }));
}

// True when the record was stored without a salt.
export function isUnsalted(record) {
  return record.salt === "";
}
