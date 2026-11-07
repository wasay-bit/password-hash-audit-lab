# Password Hash Audit Lab

A practice project that shows why weak passwords and fast, unsalted hashes are easy to guess. It runs a small word-list check against fictional sample hashes.

> **Authorship:** Written by AI (Claude) as a practice project.

## Safety

- This is a lab tool. The sample data is **fictional**, and the command reads only the bundled sample file. It takes no file path.
- It does not connect to any login system or network.
- Don't use it against real accounts or password data you don't own.

## What it shows

- **Unsalted, fast hashes fall quickly.** `alice`, `bob` have no salt. Their weak passwords are guessed from the word list.
- **Salt stops shared tables, but not weak passwords.** `dave` has a salt, but `letmein` is still guessed, because the attacker checks each word with that salt.
- **Long, random passwords hold.** `carol` (a long passphrase) and `erin` (random) aren't on the list.

The hashes use SHA-256 on purpose, to keep the lab fast. Real systems should use a slow password hash such as scrypt, bcrypt, or argon2.

## Run it

```bash
node cli.js       # audit the sample file
npm test          # run the tests
```

Requires Node.js 18 or newer. There are no packages to install.

## Files

- `lib/audit.js`: the hashing and word-list check.
- `cli.js`: runs the audit on the bundled sample.
- `data/sample-hashes.json`: fictional users and hashes.
- `data/common-passwords.txt`: a short list of common passwords.
- `test/audit.test.js`: tests for the check and the sample results.
- `.gitlab-ci.yml`: runs the tests on every push.

## Limitations

- The word list is tiny. Real attacks use lists with millions of entries and rules for common patterns.
- Only the sample file is included. The tool isn't meant for real data.
