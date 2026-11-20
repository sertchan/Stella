<img width="3840" height="2160" alt="Stella" src="https://github.com/user-attachments/assets/4d9e0218-3413-4854-9780-f49853d450b6" />

> [!CAUTION]
> Stella is currently in beta and under active development. Detection algorithms, features, and outputs may change, and occasional false positives can occur.

## Who is Stella, and what is its purpose?

The Stella project was built to bring years of ongoing internet scanning for developing Content Blocker and DNS Blocklist projects into an auditable, accountable, well-documented, and completely open and free structure.

Stella avoids relying on name-based domain guessing. Guessing by name is a crude method that can produce a large number of false positives. Given the thousands of companies, independent developers, and millions of domains worldwide, predicting how people name their domains offers a decent baseline, yet falls far short of high accuracy.

Instead, Stella analyzes behavior. It is meticulous and obsessive. Domains may change and new ones may be created, yet new and changing domains still carry on their old habits.

Stella frequently uses attack surface discovery techniques familiar from cybersecurity. It excels at neutralizing domains as soon as they are created, often before they are even put to use. This allows a domain to be discovered and blocked before it ever appears in the logs of millions of people.

Finding and blocking a domain is only the beginning. Because Stella feeds lists used by millions of people around the world, it is equally rigorous about variants and excels at uncovering all country-specific and modified variants of a tracker family.

Beyond finding new domains, Stella also uses domains already present in our lists as seeds, proving highly effective at discovering their variants.

When scanning for false positives, Stella inspects every domain across our lists in addition to its own findings, detecting other domains that break websites and applications due to the same cause and behavioral pattern.

Stella is an actively developed project that places great importance on user feedback, as a single false positive can expose a flaw in the algorithm. Once that flaw is resolved, every domain blocked for the same reason can be located and removed from our lists.

*Stella* means "star" in Latin, and this name is no coincidence. We hope it illuminates the dark corners of the internet before we ever reach them and guides our way.
