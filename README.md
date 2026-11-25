# Password Hash Audit Lab

A practice project that shows what an attacker learns from a stolen password table. It runs a small word-list check against a set of fictional password hashes for a made-up company, then reports which accounts fall, which hold, and where salt does and does not help.

> **Authorship:** Written by AI (Claude) as a practice project. The data is fictional, and the checks are deliberately simple.

## The problem

When a password database leaks, the attacker does not have passwords. They have hashes. How much that hurts depends on two choices the site made: whether it used a salt, and whether it used a slow hash. It also depends on the users: a long passphrase survives even a weak setup, and `letmein` does not.

This lab makes that concrete. `data/sample-hashes.json` is a fake company, **Larkspur Logistics**, with 17 fictional staff across five teams. Some accounts are stored without a salt, some with one. Some people picked common passwords, one reused another person's, and a few chose long random ones.

## Safety

- The data is **fictional**: made-up names, roles and passwords. None of these hashes belong to a real person.
- The command reads only the bundled file in `data/`. It takes no file path, so it cannot be pointed at other data.
- It does not connect to any login system or network.
- Don't use it against real accounts or password data you don't own.

## What it shows

| Result | Who | Why it matters |
|---|---|---|
| Guessed, no salt | `alice.reyes`, `bob.nakamura`, `frank.moreau`, `keiko.tanaka`, `noah.patel`, `priya.raman`, `quinn.baker` | A common password falls instantly, and an unsalted hash can be looked up in a precomputed table. |
| Guessed, salted | `dave.osei`, `grace.lin`, `jamal.wright`, `luis.ortega`, `olga.petrova` | The salt stops shared tables, but the attacker just tries each word with that user's salt. Salt does not save a weak password. |
| Shared passwords | `frank.moreau` and `grace.lin` (`qwerty`); `keiko.tanaka` and `olga.petrova` (`shadow`); `priya.raman` and `quinn.baker` (`welcome`) | One leak now exposes several accounts. Reuse matters even when the password is strong. |
| Identical hashes | `priya.raman` and `quinn.baker` | Without a salt, the same password gives the same hash, so a shared password is visible before any guessing. |
| Held | `carol.diaz`, `erin.fischer`, `maria.rossi` (long passphrases or random strings), `hector.silva`, `irene.kowalski` (patterns the word list does not cover) | Length and randomness do the most work. |

`hector.silva` (`Larkspur2024!`) and `irene.kowalski` (`P@ssw0rd!`) show the limit of this lab: they are weak in a real attack, but this word list does not contain them. A real attack uses millions of words plus rules that try capitalisation, years, and letter swaps such as `a` to `@`. They are in the data on purpose, so the report is honest about what a short list misses.

The hashes use SHA-256 on purpose, to keep the lab fast. Real systems should use a slow password hash such as scrypt, bcrypt, or argon2, which makes each guess expensive.

## Run it

```bash
node cli.js       # audit the fictional sample and print the report
npm test          # run the tests
```

Requires Node.js 18 or newer. There are no packages to install.

The tests also run on every push and pull request through GitHub Actions (`.github/workflows/tests.yml`).

## Files

- `lib/audit.js`: hashing, the word-list check, the summary, and the shared-password and identical-hash checks.
- `cli.js`: runs the audit on the bundled sample and prints the report.
- `data/sample-hashes.json`: the fictional company, users, roles, salts and hashes.
- `data/common-passwords.txt`: a short list of common passwords.
- `test/audit.test.js`: tests for the hashing, the checks, and the expected results for the sample.
- `WRITEUP.md`: what the project shows and what it doesn't.

## Limitations

- The word list is tiny, 26 words. Real attacks use lists with millions of entries and mangling rules. A password missing here is not safe, only untested.
- The data is small and invented. It shows the shape of the problem, not real breach statistics.
- Only SHA-256 is modelled. It does not time a slow hash, which is the defence that actually matters.
- Only the bundled sample file is read. The tool is not built for real data.
