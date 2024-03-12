---
title: "GhostRace: Exploiting and Mitigating Speculative Race Conditions"
tags: security transient-execution
authors: ["Hany",  "Andrea", "Anil", "Cristiano"]
bibtex: |
    @INPROCEEDINGS{usenix2024ghostrace,
        author={Ragab Hany and Andrea Mambretti and Anil Kurmus and Cristiano Giuffrida},
        booktitle={(to appear) 33rd USENIX Security Symposium (USENIX Security 24)},
        title={{GhostRace}: Exploiting and Mitigating Speculative Race Conditions},
        year={2024},
    }
---
[GhostRace (CVE-2024-2193)](https://www.vusec.net/projects/ghostrace) is a new attack combining speculative execution and race conditions, two very challenging class of attacks.

Race conditions arise when multiple threads attempt to access a shared resource without proper synchronization, often leading to vulnerabilities such as concurrent use-after-free. To mitigate their occurrence, operating systems rely on synchronization primitives such as mutexes, spinlocks, etc.

Our key finding is that all the common synchronization primitives implemented using conditional branches can be microarchitecturally bypassed on speculative paths using a branch misprediction attack, turning all architecturally race-free critical regions into Speculative Race Conditions (SRCs), allowing attackers to leak information from the target.

[As in previous work]( {{ site.baseurl }}{% link _posts/2021-06-18-SPEAR-attacks-SSP-usecase.md %}), this demonstrates the power attackers can have in combining memory corruption attacks - here concurrent use-after-free - with memory corruption attacks.
  
Read our upcoming [USENIX Security'24 paper](https://download.vusec.net/papers/ghostrace_sec24.pdf) and [Github repo](https://github.com/vusec/ghostrace) for more details, including scripts to find vulnerable gadgets, our suggested mitigation, and the mitigation plans for Linux.

# Endnotes
