# Write-up: Password Hash Audit Lab

> **Authorship:** Written by AI (Claude) as a practice project.

## The problem

A leaked password database contains hashes, not passwords. Whether those hashes turn back into passwords depends on choices the site made years earlier, and on choices the users made. The common advice ("use a salt") is only half the answer, and this lab exists to show the other half.

## What I built

A small Node.js project with no dependencies:

1. A fictional company, **Larkspur Logistics**, with 17 invented staff, their roles, and their password hashes. Some records have a salt, some do not.
2. A word-list check: hash each word with the record's own salt and compare. That is all an offline attack needs.
3. A report that separates the results by case: guessed without a salt, guessed with one, shared passwords, identical hashes, and held.

## What the data shows

- **Salt is not a defence against weak passwords.** Five salted accounts fall to the same 26-word list. The salt changes the hash, but the attacker has the salt: it is stored next to the hash.
- **Salt is a defence against shared tables and against visible reuse.** Without a salt, two people with the same password have the same hash, so `priya.raman` and `quinn.baker` are visibly linked before any guessing. Every salted record in the sample has a unique hash.
- **Password reuse turns one leak into several.** Three passwords are shared by two users each.
- **Length and randomness are what actually hold.** The five accounts that survive are long passphrases, random strings, or patterns this short list does not cover.

## Decisions worth explaining

- **Two users were deliberately left uncracked but weak.** `Larkspur2024!` and `P@ssw0rd!` are bad passwords that this list misses. Including them keeps the report honest: a clean result from a small word list means "not tested", not "safe".
- **Roles are included.** The warehouse team has the most guessed passwords, which is the kind of pattern a real audit reports and a training programme acts on.
- **The tool cannot take a file path.** It reads only the bundled sample. A lab tool that can be pointed at real password data is a liability, so the option does not exist.
- **Fast hash on purpose.** SHA-256 keeps the lab instant. The README says plainly that real systems need a slow hash, because otherwise the lab would teach the wrong lesson.
- **Tests assert the exact results.** If someone edits the sample data, the tests fail and the README table has to be updated too. That keeps the write-up from drifting away from the data.

## What I learned

- Salting and slowness solve different problems. Salt defeats precomputation and hides reuse. Only slowness makes guessing expensive.
- A small word list produces a misleadingly clean result. The interesting part of the report is the "not guessed" list, because that is where the limits hide.
- Fictional data has to be designed, not just generated. The sample only teaches anything because specific cases were placed in it on purpose.

## Limits

- 26 words, no mangling rules. A real attack would guess `Larkspur2024!` and `P@ssw0rd!` easily.
- SHA-256 only. No timing comparison between fast and slow hashes.
- 17 invented users. Enough to show patterns, not enough to say anything statistical.

## Next steps I would take

- Add mangling rules: capitalise, append a year, swap letters for look-alikes. Then show how many more accounts fall.
- Time the same word list against scrypt with realistic parameters, to show the cost difference.
- Add a "what to do" section per finding: force a reset, enable a breach check, block the top 10,000 passwords.
