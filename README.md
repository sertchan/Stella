<img width="3840" height="2160" alt="Stella" src="https://github.com/user-attachments/assets/4d9e0218-3413-4854-9780-f49853d450b6" />

> [!CAUTION]
> Stella is currently in beta and under active development. Detection algorithms, features, and outputs may change, and occasional false positives can occur.

## Stella: Behavioral Domain Detection Infrastructure

The Stella project was established to integrate years of ongoing internet scanning for the development of Content Blocker and DNS Blocklist initiatives into an auditable, accountable, well-documented, and openly accessible infrastructure.

Stella avoids reliance on name-based domain guessing, which is a crude heuristic capable of generating substantial false positives. Considering the thousands of organizations, independent developers, and millions of domains globally, modeling domain naming conventions provides a reasonable baseline yet remains far from high precision.

Instead, Stella evaluates behavioral patterns. Although domains may be modified or newly registered, emerging and evolving domains tend to retain prior operational habits.

Stella frequently employs attack surface discovery methods established in cybersecurity. It is particularly effective at mitigating newly provisioned domains, often prior to active deployment, enabling detection and blocking before such domains appear in the resolver logs of millions of users.

Identifying and blocking a domain represents only the initial step. Because Stella supplies blocklists utilized by millions of users worldwide, it maintains comparable rigor with domain variants, effectively uncovering regional and modified variants within a tracker family.

Beyond identifying novel domains, Stella also utilizes existing list entries as seeds, demonstrating high efficacy in surfacing associated variants.

During false-positive auditing, Stella examines all domains across existing lists alongside its own detections, identifying additional domains that breaks websites and applications due to the same underlying cause and behavioral pattern.

Stella is an actively maintained project that places substantial weight on user feedback, as a single false positive can reveal an algorithmic flaw. Once the underlying issue is addressed, all domains blocked for the same reason can be identified and removed from the lists.