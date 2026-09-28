# Security policy

AttackGraph stores a model of how an environment could be compromised. Vulnerabilities in it
matter, and so does the way they are reported. Thank you for helping keep the project and
its users safe.

## Supported versions

AttackGraph has not published a release. Security fixes are made on the `main` branch only.

## Reporting a vulnerability

**Do not report vulnerabilities in public issues, pull requests, discussions or commits.**
Do not include exploit details, affected configurations, credentials, or data from any real
environment in any public place.

This repository does not currently have GitHub private vulnerability reporting enabled, and
the project does not publish a security email address. To report a vulnerability:

1. Contact the maintainer, [@WiseHax](https://github.com/WiseHax), privately using a contact
   method listed on their GitHub profile, and ask for a private channel to share details.
2. If no private contact method is available, open a **minimal** public issue titled
   "Request for private security contact" that contains **no** vulnerability details. The
   maintainer will arrange a private channel.

Please include, once a private channel is established:

- a description of the issue and its potential impact
- the affected component, file or commit
- steps to reproduce, using synthetic data only
- any suggested fix or mitigation

The project is maintained on a best-effort basis; there is no guaranteed response time or bug
bounty. Please allow reasonable time for a fix before any public disclosure.

## General security questions

Questions about hardening or security design that do **not** involve an undisclosed
vulnerability can be raised in a regular issue.

## Scope and intended use

AttackGraph is intended only for defensive analysis of environments you are authorized to
assess. It does not scan, probe or exploit systems, and requests to add such capabilities are
out of scope (see [Security engineering rules](docs/security/SECURITY_ENGINEERING_RULES.md)).
