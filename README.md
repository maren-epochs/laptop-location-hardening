# Location-Hardening a Laptop Against a Host-Resident Observer

A design and verification case study: making a Windows laptop present as "at home" to any software running on it, wherever it physically is.

The full write-up is in **[EXPLAINER.md](EXPLAINER.md)** (about ten pages). It covers the threat model, why the conventional answers (a VPN on the laptop, the Windows location toggle, browser settings) fail against a process-aware observer, a thirteen-row inventory of location-leak channels and their controls, the travel-router architecture that keeps the laptop free of any VPN footprint, a fail-loud PowerShell self-test with reversible one-switch hardening, the hardware evaluation, the operating procedure, and the lessons learned.

Identifying details have been removed. The verification script is described but not published.

Author: [maren-epochs](https://github.com/maren-epochs)
