# Security Policy

Fraptix is a security tool, and we take security reports seriously.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report them privately through GitHub's Security Advisories:

1. Go to the **Security** tab of the repository:
   <https://github.com/ishtiyaq130/fraptix/security>
2. Click **Report a vulnerability**.
3. Describe the issue with as much detail as possible: affected version,
   steps to reproduce, and potential impact.

You can expect:

- An acknowledgment within 5 business days.
- A status update within 14 days.
- Credit in the release notes if you wish.

## What to include

- Affected Fraptix version(s)
- Steps to reproduce (a minimal code sample helps a lot)
- Impact and possible exploit scenario
- Any suggested fix you may have

## Scope

Security reports are welcome for:

- Vulnerabilities in Fraptix itself (the analyzer)
- False negatives that let dangerous code patterns slip through
- Unsafe handling of scanned source code (e.g. path traversal while scanning)

We do **not** consider findings that Fraptix reports about your own
application to be vulnerabilities in Fraptix — that is the tool doing its job.

## Disclosure process

1. The report is acknowledged and triaged.
2. A fix is prepared and released.
3. The advisory is published after the fix is available, with credit to the
   reporter (unless they prefer to remain anonymous).
