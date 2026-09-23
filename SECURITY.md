# Security Policy

Morse is a development implementation and does not make a production-security claim.

Report suspected vulnerabilities privately through GitHub's **Security → Report a vulnerability** flow. Do not open a public issue or include real keys, message contents, account data, or production credentials in a report.

Include the affected revision, component, reproduction steps, impact, and whether disclosure is time-sensitive. Maintainers will acknowledge the report, reproduce and triage it privately, coordinate a fix and retest, and publish an advisory when disclosure is safe.

The supported security-test target is the current `main` revision. Classical, experimental hybrid (`0x0002`), and custom group (`0x0003`) code is reachable. Release readiness requires successful internal verification of the exact Morse and Mesh commits, applicable platform evidence, and resolution or exclusion of known security failures. Outside review is additional scrutiny, not a prerequisite; no independent audit is claimed.
