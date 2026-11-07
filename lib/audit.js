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
