# Security Policy

NetLanvas runs with elevated network privileges on your own LAN by design
— it needs to, to do its job — which means we take security issues in
this codebase seriously, and we'd rather hear about a problem directly
than have it found for us.

## Reporting a vulnerability

Email **security@netlanvas.com**. Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept if you have one
- The version/commit you tested against

You'll get an acknowledgement within 3 business days. We'll keep you
updated as we investigate and fix, and we're happy to credit reporters in
the eventual release notes if you'd like — just say so in your report.

Please report privately first and give us a reasonable window to ship a
fix before any public disclosure. We're a small team; we'll move as fast
as we genuinely can, and we'll tell you our estimate once we've looked at
the report rather than leaving you guessing.

This address is also published via [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
`security.txt` at [netlanvas.com/.well-known/security.txt](https://netlanvas.com/.well-known/security.txt).

## Scope

This repository is the NetLanvas appliance/client — everything that runs
on your own device. It's the appropriate place to report issues in
discovery, scanning, the local web UI, or anything else that runs here.

NetLanvas's account/entitlement/payment backend is a separate, closed-source
system not contained in this repository. Issues there are still in scope
for reports to the same address above — you don't need to know which side
of the system a bug lives in before reporting it.

## Supported versions

We support the latest released version. If you're not running the latest
release, please update and confirm the issue still reproduces before
reporting, where practical.

## What to expect from us

We'll tell you plainly what we know and don't know. We won't ask you to
sit on a report indefinitely, and we won't publish exploit-level detail
about past issues after they're fixed — patched vulnerabilities are
described in release notes at a level that lets users understand what
changed and why an update matters, not as a how-to.
