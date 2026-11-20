<img width="3840" height="2160" alt="Stella" src="https://github.com/user-attachments/assets/4d9e0218-3413-4854-9780-f49853d450b6" />

> [!CAUTION]
> Stella is currently in beta and under active development. Detection algorithms, features, and outputs may change, and occasional false positives can occur.

## Stella: Behavioral Domain Detection Infrastructure

Stella was created to turn years of ongoing internet scanning for Content Blockers and DNS Blocklists into an open, auditable, accountable, and well-documented infrastructure.
Stella avoids relying on name-based domain guessing, a rough heuristic that creates too many false positives. With thousands of organizations, independent developers, and millions of domains on the web, modeling naming patterns offers a decent baseline, though it stays far from high precision.
Instead, Stella looks at behavioral patterns. Even when domains are modified or newly registered, they tend to keep their previous operational habits.
Stella frequently uses attack surface discovery techniques from cybersecurity. It is especially effective at catching newly provisioned domains, often before they go live, making it possible to detect and block them before they ever show up in the resolver logs of millions of users.
Finding and blocking a domain is only the first step. Because millions of users worldwide rely on Stella's blocklists, it applies the same rigor to domain variants, reliably uncovering regional and modified variants within a tracker family.
On top of finding new domains, Stella also uses existing list entries as seeds, proving very effective at surfacing related variants.
During false-positive audits, Stella checks all domains across existing lists alongside its own detections to spot other domains that break websites and apps for the same underlying reason and behavioral pattern.
Stella is an actively maintained project that takes user feedback seriously, since a single false positive can expose a flaw in the algorithm. Once the underlying issue is fixed, every domain blocked for that same reason can be found and removed from the lists.
